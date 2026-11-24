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

    // Asks the person to confirm (user presence). Fallback = "use another security key" (the browser's own).
    internal interface IConsent
    {
        Decision Ask(bool isCreate, string rpId);
    }

    // Software security key: answers WebAuthn create/get requests (from the extension) the way a
    // CTAP2 authenticator would, with "none" attestation and non-discoverable credentials.
    //
    // Request:  { type: "create" | "get", origin: "https://...", options: <publicKey options, binary as base64url> }
    // Reply:    { status: "ok", credential: { id, rawId, type, authenticatorAttachment, response, clientExtensionResults } }
    //        or { status: "error", name: <DOMException name>, message, fallback: <true = let the browser handle it> }
    //
    // The origin comes from the browser (sender.origin in the extension), never from the page.
    internal static class Authenticator
    {
        // Phase 1 is scoped to Google (and webauthn.io for testing).
        internal static readonly string[] AllowedRpIds = { "google.com", "webauthn.io" };

        private const byte FlagUserPresent = 0x01;
        private const byte FlagAttestedData = 0x40;
        private const int MinChallenge = 16;
        private static readonly byte[] Aaguid = new byte[16];
        private static readonly byte[] ZeroCounter = new byte[4]; // 0 = no counter (allowed by WebAuthn)

        internal static Dictionary<string, object> Handle(
            Dictionary<string, object> req, IConsent consent, Func<bool, byte[]> loadMaster)
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
            return type == "create" ? Create(opt, origin, host, consent, loadMaster) : Get(opt, origin, host, consent, loadMaster);
        }

        private static Dictionary<string, object> Create(
            Dictionary<string, object> opt, string origin, string host, IConsent consent, Func<bool, byte[]> loadMaster)
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
            Dictionary<string, object> sel = Json.Map(opt, "authenticatorSelection");
            if (sel != null && (Json.Str(sel, "residentKey") == "required" || Json.Bool(sel, "requireResidentKey")
                || Json.Str(sel, "userVerification") == "required" || Json.Str(sel, "authenticatorAttachment") == "platform"))
            {
                return Error("NotSupportedError", "The site wants a passkey PlugPass can't make yet.", true);
            }
            byte[] challenge = Bytes.FromB64Url(Json.Str(opt, "challenge"));
            Dictionary<string, object> user = Json.Map(opt, "user");
            byte[] userHandle = user == null ? null : Bytes.FromB64Url(Json.Str(user, "id"));
            if (challenge == null || challenge.Length < MinChallenge || userHandle == null || userHandle.Length == 0
                || userHandle.Length > CredentialWrap.MaxUserHandle)
            {
                return Error("TypeError", "The site sent an invalid request.", false);
            }

            byte[] rpIdHash = Bytes.Sha256(Bytes.Utf8(rpId));
            byte[] master = loadMaster(false);
            if (master != null && FindOurs(master, rpIdHash, Json.Arr(opt, "excludeCredentials")) != null)
            {
                // Ask first (like touching a hardware key), so a site can't silently probe for the key.
                consent.Ask(true, rpId);
                return Error("InvalidStateError", "This PlugPass key is already registered with this account.", false);
            }
            Decision d = consent.Ask(true, rpId);
            if (d != Decision.Allow)
            {
                return DecisionError(d);
            }
            if (master == null)
            {
                master = loadMaster(true);
            }

            byte[] blob = EcKey.Generate();
            byte[] credId = CredentialWrap.Wrap(master, rpIdHash, blob, userHandle);
            byte[] clientData = ClientData("webauthn.create", challenge, origin);
            byte[] authData = Bytes.Concat(
                rpIdHash, new byte[] { FlagUserPresent | FlagAttestedData }, ZeroCounter, Aaguid,
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
            return Ok(credId, response);
        }

        private static Dictionary<string, object> Get(
            Dictionary<string, object> opt, string origin, string host, IConsent consent, Func<bool, byte[]> loadMaster)
        {
            string rpId = Json.Str(opt, "rpId");
            Dictionary<string, object> check = CheckRp(host, ref rpId);
            if (check != null)
            {
                return check;
            }
            if (Json.Str(opt, "userVerification") == "required")
            {
                return Error("NotSupportedError", "The site wants a PIN-verified key; PlugPass adds that in phase 2.", true);
            }
            object[] allow = Json.Arr(opt, "allowCredentials");
            if (allow == null || allow.Length == 0)
            {
                return Error("NotSupportedError", "The site wants a passkey PlugPass can't use yet.", true);
            }
            byte[] master = loadMaster(false);
            if (master == null)
            {
                return Error("NotAllowedError", "No PlugPass key is set up.", true);
            }
            byte[] rpIdHash = Bytes.Sha256(Bytes.Utf8(rpId));
            byte[] credId;
            CredentialWrap.Contents found = FindOurs(master, rpIdHash, allow, out credId);
            if (found == null)
            {
                return Error("NotAllowedError", "This account doesn't use this PlugPass key.", true);
            }
            byte[] challenge = Bytes.FromB64Url(Json.Str(opt, "challenge"));
            if (challenge == null || challenge.Length < MinChallenge)
            {
                return Error("TypeError", "The site sent an invalid request.", false);
            }
            Decision d = consent.Ask(false, rpId);
            if (d != Decision.Allow)
            {
                return DecisionError(d);
            }

            byte[] clientData = ClientData("webauthn.get", challenge, origin);
            byte[] authData = Bytes.Concat(rpIdHash, new byte[] { FlagUserPresent }, ZeroCounter);
            byte[] signature = EcKey.Sign(found.KeyBlob, Bytes.Concat(authData, Bytes.Sha256(clientData)));
            Array.Clear(found.KeyBlob, 0, found.KeyBlob.Length);

            Dictionary<string, object> response = new Dictionary<string, object>();
            response["clientDataJSON"] = Bytes.ToB64Url(clientData);
            response["authenticatorData"] = Bytes.ToB64Url(authData);
            response["signature"] = Bytes.ToB64Url(signature);
            response["userHandle"] = found.UserHandle.Length == 0 ? null : Bytes.ToB64Url(found.UserHandle);
            return Ok(credId, response);
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

        private static CredentialWrap.Contents FindOurs(byte[] master, byte[] rpIdHash, object[] list)
        {
            byte[] ignored;
            return FindOurs(master, rpIdHash, list, out ignored);
        }

        private static CredentialWrap.Contents FindOurs(byte[] master, byte[] rpIdHash, object[] list, out byte[] credId)
        {
            credId = null;
            if (list == null)
            {
                return null;
            }
            foreach (object o in list)
            {
                Dictionary<string, object> desc = o as Dictionary<string, object>;
                byte[] id = desc == null ? null : Bytes.FromB64Url(Json.Str(desc, "id"));
                CredentialWrap.Contents c = CredentialWrap.Unwrap(master, id);
                if (c != null && Bytes.FixedTimeEquals(c.RpIdHash, rpIdHash))
                {
                    credId = id;
                    return c;
                }
            }
            return null;
        }

        private static byte[] ClientData(string type, byte[] challenge, string origin)
        {
            return Bytes.Utf8("{\"type\":\"" + type + "\",\"challenge\":\"" + Bytes.ToB64Url(challenge)
                + "\",\"origin\":\"" + Json.Escape(origin) + "\",\"crossOrigin\":false}");
        }

        private static Dictionary<string, object> Ok(byte[] credId, Dictionary<string, object> response)
        {
            Dictionary<string, object> cred = new Dictionary<string, object>();
            cred["id"] = Bytes.ToB64Url(credId);
            cred["rawId"] = Bytes.ToB64Url(credId);
            cred["type"] = "public-key";
            cred["authenticatorAttachment"] = "cross-platform";
            cred["response"] = response;
            cred["clientExtensionResults"] = new Dictionary<string, object>();
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
