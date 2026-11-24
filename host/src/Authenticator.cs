using System;
using System.Collections.Generic;

namespace PlugPass
{
    internal enum Decision
    {
        Allow,
        Fallback,
        Cancel,
    }

    internal sealed class PinQuestion
    {
        internal bool IsCreate;
        internal string RpId;
        internal int TriesLeft;
        internal string Error;
    }

    internal sealed class PinAnswer
    {
        internal Decision Decision;
        internal string Pin;
    }

    // The person's side: PIN entry (user presence + verification), account choice, short notices.
    // Fallback = "use another security key" (the browser's own).
    internal interface IPinPrompt
    {
        PinAnswer AskPin(PinQuestion q);

        // Index of the chosen account, or -1 to cancel.
        int ChooseAccount(string rpId, string[] accounts);

        void Tell(string message);
    }

    // Security key backed by the PlugPass USB drive: answers WebAuthn create/get requests (from the
    // extension) like a CTAP2 authenticator with a PIN: "none" attestation, user verification by PIN,
    // a signature counter, and passkeys (discoverable credentials) stored on the drive.
    //
    // Request:  { type: "create" | "get", origin: "https://...", options: <publicKey options, binary as base64url> }
    // Reply:    { status: "ok", credential: { id, rawId, type, authenticatorAttachment, response, clientExtensionResults } }
    //        or { status: "error", name: <DOMException name>, message, fallback: <true = let the browser handle it> }
    //
    // The origin comes from the browser (sender.origin in the extension), never from the page.
    // No drive, a damaged drive, or a drive from another PC: silent fallback, so the password and the
    // browser's own security keys always keep working.
    internal static class Authenticator
    {
        internal static readonly string[] AllowedRpIds = { "google.com", "webauthn.io" };

        private const byte FlagUserPresent = 0x01;
        private const byte FlagUserVerified = 0x04;
        private const byte FlagAttestedData = 0x40;
        private const int MinChallenge = 16;
        private const int MaxNameLength = 64;
        private static readonly byte[] Aaguid = new byte[16];

        internal static Dictionary<string, object> Handle(
            Dictionary<string, object> req, IPinPrompt prompt, Func<string> findDrive)
        {
            string type = Json.Str(req, "type");
            Dictionary<string, object> opt = Json.Map(req, "options");
            if (opt == null || (type != "create" && type != "get"))
            {
                return Error("NotSupportedError", "Unknown request.", true);
            }
            string origin = Json.Str(req, "origin");
            string host = OriginHost(origin);
            if (host == null)
            {
                return Error("SecurityError", "Only secure (https) pages can use PlugPass.", false);
            }
            using (KeyLock held = KeyLock.Acquire(LockTimeoutMs))
            {
                if (held == null)
                {
                    return Error("NotAllowedError", "Another PlugPass window is still open.", true);
                }
                return type == "create" ? Create(opt, origin, host, prompt, findDrive) : Get(opt, origin, host, prompt, findDrive);
            }
        }

        private const int LockTimeoutMs = 3 * 60 * 1000;

        private static Dictionary<string, object> Create(
            Dictionary<string, object> opt, string origin, string host, IPinPrompt prompt, Func<string> findDrive)
        {
            Dictionary<string, object> rp = Json.Map(opt, "rp");
            string rpId = rp == null ? null : Json.Str(rp, "id");
            Dictionary<string, object> check = CheckRp(host, ref rpId);
            if (check != null)
            {
                return check;
            }
            if (!OffersEs256(Json.Arr(opt, "pubKeyCredParams")))
            {
                return Error("NotSupportedError", "The site doesn't accept PlugPass's key type.", true);
            }
            Dictionary<string, object> sel = Json.Map(opt, "authenticatorSelection") ?? new Dictionary<string, object>();
            if (Json.Str(sel, "authenticatorAttachment") == "platform")
            {
                return Error("NotSupportedError", "The site wants this device's own authenticator.", true);
            }
            string residentKey = Json.Str(sel, "residentKey");
            bool resident = residentKey == "required" || residentKey == "preferred" || Json.Bool(sel, "requireResidentKey");
            byte[] challenge = Bytes.FromB64Url(Json.Str(opt, "challenge"));
            Dictionary<string, object> user = Json.Map(opt, "user");
            byte[] userHandle = user == null ? null : Bytes.FromB64Url(Json.Str(user, "id"));
            if (challenge == null || challenge.Length < MinChallenge || userHandle == null || userHandle.Length == 0
                || userHandle.Length > CredentialWrap.MaxUserHandle)
            {
                return Error("TypeError", "The site sent an invalid request.", false);
            }

            Dictionary<string, object> error;
            KeyFile kf = FindKey(findDrive, out error);
            if (kf == null)
            {
                return error;
            }
            byte[] rpIdHash = Bytes.Sha256(Bytes.Utf8(rpId));
            List<byte[]> excluded = OwnIds(Json.Arr(opt, "excludeCredentials"), kf.KeyId);
            if (!UnlockWithPin(kf, true, rpId, prompt, out error))
            {
                return error;
            }
            KeyPayload p = kf.Payload;
            foreach (byte[] id in excluded)
            {
                CredentialWrap.Contents c = CredentialWrap.Unwrap(p.Master, id);
                if (c != null && Bytes.FixedTimeEquals(c.RpIdHash, rpIdHash))
                {
                    return Error("InvalidStateError", "This PlugPass key is already registered with this account.", false);
                }
            }

            byte[] blob = EcKey.Generate();
            byte[] credId = CredentialWrap.Wrap(p.Master, kf.KeyId, rpIdHash, blob, userHandle);
            p.Counter++;
            if (resident)
            {
                string handle = Bytes.ToB64Url(userHandle);
                p.Passkeys.RemoveAll(k => k.RpId == rpId && k.UserHandle == handle);
                Passkey pk = new Passkey();
                pk.RpId = rpId;
                pk.CredId = Bytes.ToB64Url(credId);
                pk.UserHandle = handle;
                pk.UserName = Clip(Json.Str(user, "name"));
                pk.DisplayName = Clip(Json.Str(user, "displayName"));
                pk.Created = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                p.Passkeys.Add(pk);
            }
            kf.Save();

            byte[] clientData = ClientData("webauthn.create", challenge, origin);
            byte[] authData = Bytes.Concat(
                rpIdHash, new byte[] { FlagUserPresent | FlagUserVerified | FlagAttestedData }, Counter(p.Counter), Aaguid,
                new byte[] { (byte)(credId.Length >> 8), (byte)credId.Length }, credId, EcKey.CoseKey(blob));
            // {"fmt": "none", "attStmt": {}, "authData": ...} in canonical key order.
            byte[] attObj = new CborWriter().Map(3)
                .Text("fmt").Text("none")
                .Text("attStmt").Map(0)
                .Text("authData").Bytes(authData)
                .ToArray();

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["clientDataJSON"] = Bytes.ToB64Url(clientData);
            response["attestationObject"] = Bytes.ToB64Url(attObj);
            response["authenticatorData"] = Bytes.ToB64Url(authData);
            response["publicKey"] = Bytes.ToB64Url(EcKey.Spki(blob));
            response["publicKeyAlgorithm"] = EcKey.CoseAlgEs256;
            response["transports"] = new[] { "usb" };
            Array.Clear(blob, 0, blob.Length);

            Dictionary<string, object> ext = new Dictionary<string, object>();
            Dictionary<string, object> requested = Json.Map(opt, "extensions");
            if (requested != null && Json.Bool(requested, "credProps"))
            {
                Dictionary<string, object> props = new Dictionary<string, object>();
                props["rk"] = resident;
                ext["credProps"] = props;
            }
            return Ok(credId, response, ext);
        }

        private static Dictionary<string, object> Get(
            Dictionary<string, object> opt, string origin, string host, IPinPrompt prompt, Func<string> findDrive)
        {
            string rpId = Json.Str(opt, "rpId");
            Dictionary<string, object> check = CheckRp(host, ref rpId);
            if (check != null)
            {
                return check;
            }
            byte[] challenge = Bytes.FromB64Url(Json.Str(opt, "challenge"));
            if (challenge == null || challenge.Length < MinChallenge)
            {
                return Error("TypeError", "The site sent an invalid request.", false);
            }
            Dictionary<string, object> error;
            KeyFile kf = FindKey(findDrive, out error);
            if (kf == null)
            {
                return error;
            }
            object[] allow = Json.Arr(opt, "allowCredentials");
            bool discoverable = allow == null || allow.Length == 0;
            List<byte[]> mine = OwnIds(allow, kf.KeyId);
            if (!discoverable && mine.Count == 0)
            {
                return Error("NotAllowedError", "This account doesn't use this PlugPass key.", true);
            }
            if (!UnlockWithPin(kf, false, rpId, prompt, out error))
            {
                return error;
            }
            KeyPayload p = kf.Payload;
            byte[] rpIdHash = Bytes.Sha256(Bytes.Utf8(rpId));

            byte[] credId = null;
            CredentialWrap.Contents found = null;
            if (discoverable)
            {
                List<Passkey> candidates = p.Passkeys.FindAll(k => k.RpId == rpId);
                if (candidates.Count == 0)
                {
                    return Error("NotAllowedError", "There's no passkey for " + rpId + " on this PlugPass drive.", true);
                }
                int pick = 0;
                if (candidates.Count > 1)
                {
                    string[] labels = candidates.ConvertAll(k => Label(k)).ToArray();
                    pick = prompt.ChooseAccount(rpId, labels);
                    if (pick < 0 || pick >= candidates.Count)
                    {
                        return Error("NotAllowedError", "Cancelled.", false);
                    }
                }
                credId = Bytes.FromB64Url(candidates[pick].CredId);
                found = CredentialWrap.Unwrap(p.Master, credId);
            }
            else
            {
                foreach (byte[] id in mine)
                {
                    CredentialWrap.Contents c = CredentialWrap.Unwrap(p.Master, id);
                    if (c != null && Bytes.FixedTimeEquals(c.RpIdHash, rpIdHash))
                    {
                        credId = id;
                        found = c;
                        break;
                    }
                }
            }
            if (found == null || !Bytes.FixedTimeEquals(found.RpIdHash, rpIdHash))
            {
                return Error("NotAllowedError", "This account doesn't use this PlugPass key.", true);
            }

            p.Counter++;
            kf.Save(); // before signing, so a counter value is never used twice
            byte[] clientData = ClientData("webauthn.get", challenge, origin);
            byte[] authData = Bytes.Concat(rpIdHash, new byte[] { FlagUserPresent | FlagUserVerified }, Counter(p.Counter));
            byte[] signature = EcKey.Sign(found.KeyBlob, Bytes.Concat(authData, Bytes.Sha256(clientData)));
            Array.Clear(found.KeyBlob, 0, found.KeyBlob.Length);

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["clientDataJSON"] = Bytes.ToB64Url(clientData);
            response["authenticatorData"] = Bytes.ToB64Url(authData);
            response["signature"] = Bytes.ToB64Url(signature);
            response["userHandle"] = found.UserHandle.Length == 0 ? null : Bytes.ToB64Url(found.UserHandle);
            return Ok(credId, response, new Dictionary<string, object>());
        }

        // The plugged-in drive's key, ready for this PC; otherwise a silent "let the browser handle it".
        private static KeyFile FindKey(Func<string> findDrive, out Dictionary<string, object> error)
        {
            error = null;
            string root = findDrive();
            if (root == null)
            {
                error = Error("NotAllowedError", "No PlugPass drive is plugged in.", true);
                return null;
            }
            KeyFile kf = KeyFile.Open(root);
            if (kf == null)
            {
                error = Error("NotAllowedError", "The PlugPass key on this drive can't be read.", true);
                return null;
            }
            byte[] pcSecret = PcSecrets.Load(kf.KeyId);
            if (pcSecret == null)
            {
                error = Error("NotAllowedError", "This PlugPass drive was set up on another PC.", true);
                return null;
            }
            Array.Clear(pcSecret, 0, pcSecret.Length);
            return kf;
        }

        // Asks for the PIN until it's right, the person gives up, or the key is erased.
        private static bool UnlockWithPin(KeyFile kf, bool isCreate, string rpId, IPinPrompt prompt, out Dictionary<string, object> error)
        {
            string problem = null;
            while (true)
            {
                PinQuestion q = new PinQuestion();
                q.IsCreate = isCreate;
                q.RpId = rpId;
                q.TriesLeft = kf.TriesLeft;
                q.Error = problem;
                PinAnswer a = prompt.AskPin(q);
                if (a == null || a.Decision != Decision.Allow)
                {
                    error = DecisionError(a == null ? Decision.Cancel : a.Decision);
                    return false;
                }
                switch (kf.Unlock(a.Pin))
                {
                    case UnlockResult.Ok:
                        error = null;
                        return true;
                    case UnlockResult.WrongPin:
                        problem = "Wrong PIN. " + kf.TriesLeft + (kf.TriesLeft == 1 ? " try" : " tries") + " left before the key is erased.";
                        continue;
                    case UnlockResult.Wiped:
                        prompt.Tell("Too many wrong PINs: the PlugPass key on this drive was erased. "
                            + "Sign in with your password and set up the drive again.");
                        error = Error("NotAllowedError", "The PlugPass key was erased after too many wrong PINs.", true);
                        return false;
                    case UnlockResult.Locked:
                        prompt.Tell("This PlugPass drive is locked after too many wrong PINs. "
                            + "Sign in with your password and set up the drive again.");
                        error = Error("NotAllowedError", "This PlugPass drive is locked.", true);
                        return false;
                    case UnlockResult.OtherPc:
                        error = Error("NotAllowedError", "This PlugPass drive was set up on another PC.", true);
                        return false;
                    default:
                        error = Error("NotAllowedError", "The PlugPass key on this drive is damaged.", true);
                        return false;
                }
            }
        }

        // "https://host[:port]" with nothing else, or null.
        internal static string OriginHost(string origin)
        {
            Uri u;
            if (string.IsNullOrEmpty(origin) || !Uri.TryCreate(origin, UriKind.Absolute, out u) || u.Scheme != Uri.UriSchemeHttps
                || !string.Equals(origin, u.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal)
                || !string.IsNullOrEmpty(u.UserInfo))
            {
                return null;
            }
            return u.IdnHost.ToLowerInvariant();
        }

        // rpId defaults to the page's host; it must be the host or a parent domain of it, and allowed.
        private static Dictionary<string, object> CheckRp(string host, ref string rpId)
        {
            if (string.IsNullOrEmpty(rpId))
            {
                rpId = host;
            }
            rpId = rpId.ToLowerInvariant();
            bool matches = rpId.IndexOf('.') > 0 && !rpId.EndsWith(".", StringComparison.Ordinal)
                && (host == rpId || host.EndsWith("." + rpId, StringComparison.Ordinal));
            if (!matches)
            {
                return Error("SecurityError", "The site name doesn't match the page.", false);
            }
            if (Array.IndexOf(AllowedRpIds, rpId) < 0)
            {
                return Error("NotSupportedError", "PlugPass works only with Google for now.", true);
            }
            return null;
        }

        private static bool OffersEs256(object[] parameters)
        {
            if (parameters == null)
            {
                return false;
            }
            foreach (object o in parameters)
            {
                Dictionary<string, object> p = o as Dictionary<string, object>;
                if (p != null && Json.Str(p, "type") == "public-key" && p.ContainsKey("alg") && p["alg"] is int
                    && (int)p["alg"] == EcKey.CoseAlgEs256)
                {
                    return true;
                }
            }
            return false;
        }

        // Credential IDs in a descriptor list that were made by this drive (checked without the PIN).
        private static List<byte[]> OwnIds(object[] list, byte[] keyId)
        {
            List<byte[]> ids = new List<byte[]>();
            if (list == null)
            {
                return ids;
            }
            foreach (object o in list)
            {
                Dictionary<string, object> desc = o as Dictionary<string, object>;
                byte[] id = desc == null ? null : Bytes.FromB64Url(Json.Str(desc, "id"));
                if (Bytes.FixedTimeEquals(CredentialWrap.KeyIdOf(id), keyId))
                {
                    ids.Add(id);
                }
            }
            return ids;
        }

        private static string Label(Passkey k)
        {
            if (k.DisplayName.Length > 0 && k.UserName.Length > 0 && k.DisplayName != k.UserName)
            {
                return k.DisplayName + " (" + k.UserName + ")";
            }
            return k.UserName.Length > 0 ? k.UserName : (k.DisplayName.Length > 0 ? k.DisplayName : "Account");
        }

        private static string Clip(string s)
        {
            if (s == null)
            {
                return "";
            }
            return s.Length > MaxNameLength ? s.Substring(0, MaxNameLength) : s;
        }

        private static byte[] Counter(uint value)
        {
            return new byte[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };
        }

        private static byte[] ClientData(string type, byte[] challenge, string origin)
        {
            return Bytes.Utf8("{\"type\":\"" + type + "\",\"challenge\":\"" + Bytes.ToB64Url(challenge)
                + "\",\"origin\":\"" + Json.Escape(origin) + "\",\"crossOrigin\":false}");
        }

        private static Dictionary<string, object> Ok(byte[] credId, Dictionary<string, object> response, Dictionary<string, object> ext)
        {
            Dictionary<string, object> cred = new Dictionary<string, object>();
            cred["id"] = Bytes.ToB64Url(credId);
            cred["rawId"] = Bytes.ToB64Url(credId);
            cred["type"] = "public-key";
            cred["authenticatorAttachment"] = "cross-platform";
            cred["response"] = response;
            cred["clientExtensionResults"] = ext;
            Dictionary<string, object> r = new Dictionary<string, object>();
            r["status"] = "ok";
            r["credential"] = cred;
            return r;
        }

        private static Dictionary<string, object> DecisionError(Decision d)
        {
            return d == Decision.Fallback
                ? Error("NotAllowedError", "Using another security key.", true)
                : Error("NotAllowedError", "Cancelled.", false);
        }

        internal static Dictionary<string, object> Error(string name, string message, bool fallback)
        {
            Dictionary<string, object> r = new Dictionary<string, object>();
            r["status"] = "error";
            r["name"] = name;
            r["message"] = message;
            r["fallback"] = fallback;
            return r;
        }
    }
}
