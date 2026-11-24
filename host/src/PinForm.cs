using System;
using System.Drawing;
using System.Windows.Forms;

namespace PlugPass
{
    // "Touch your key" + PIN in one step: PlugPass never signs anything until the right PIN is typed
    // here. It names the site, so a sign-in started somewhere unexpected stands out. The PIN is typed
    // in this window, never in a web page.
    internal sealed class PinForm : Form
    {
        private readonly TextBox _pin;
        private readonly Label _error;
        private Decision _decision = Decision.Cancel;

        internal PinForm(PinQuestion q)
        {
            Text = "PlugPass";
            Font = new Font("Segoe UI", 9f);
            AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            TopMost = true;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(16);

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.AutoSize = true;
            layout.ColumnCount = 1;
            layout.Dock = DockStyle.Fill;

            Label title = NewLabel(q.IsCreate ? "Add your PlugPass key to " + q.RpId + "?" : "Sign in to " + q.RpId + " with PlugPass?", 8);
            title.Font = new Font("Segoe UI Semibold", 11f);
            layout.Controls.Add(title);
            layout.Controls.Add(NewLabel("Only continue if you started this yourself on " + q.RpId + ". Enter your PlugPass PIN:", 8));

            _pin = new TextBox();
            _pin.UseSystemPasswordChar = true;
            _pin.MaxLength = KeyFile.MaxPinLength;
            _pin.Width = 260;
            _pin.Margin = new Padding(0, 0, 0, 8);
            layout.Controls.Add(_pin);

            _error = NewLabel(q.Error ?? "", 8);
            _error.ForeColor = Color.FromArgb(196, 43, 28);
            _error.Visible = !string.IsNullOrEmpty(q.Error);
            layout.Controls.Add(_error);

            if (q.TriesLeft <= 3)
            {
                Label warn = NewLabel("After " + q.TriesLeft + " more wrong " + (q.TriesLeft == 1 ? "PIN" : "PINs")
                    + ", the key on this drive is erased.", 8);
                warn.ForeColor = Color.FromArgb(157, 93, 0);
                layout.Controls.Add(warn);
            }

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Dock = DockStyle.Fill;
            buttons.Margin = new Padding(0, 8, 0, 0);
            Button cancel = NewButton("Cancel", Decision.Cancel);
            Button other = NewButton("Use another key", Decision.Fallback);
            Button allow = NewButton(q.IsCreate ? "Add" : "Sign in", Decision.Allow);
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(other);
            buttons.Controls.Add(allow);
            layout.Controls.Add(buttons);

            Controls.Add(layout);
            AcceptButton = allow;
            CancelButton = cancel;
            Shown += delegate { Activate(); _pin.Focus(); };
        }

        internal Decision Decision
        {
            get { return _decision; }
        }

        internal string Pin
        {
            get { return _pin.Text; }
        }

        private static Label NewLabel(string text, int bottom)
        {
            Label l = new Label();
            l.AutoSize = true;
            l.MaximumSize = new Size(420, 0);
            l.Text = text;
            l.Margin = new Padding(0, 0, 0, bottom);
            return l;
        }

        private Button NewButton(string text, Decision d)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.MinimumSize = new Size(88, 28);
            b.Margin = new Padding(8, 0, 0, 0);
            b.Click += delegate
            {
                if (d == Decision.Allow && _pin.Text.Length < KeyFile.MinPinLength)
                {
                    // Too short to be the PIN: say so without spending one of the tries.
                    _error.Text = "Your PIN has at least " + KeyFile.MinPinLength + " characters.";
                    _error.Visible = true;
                    _pin.Focus();
                    return;
                }
                _decision = d;
                Close();
            };
            return b;
        }
    }

    // Shown when one site has several accounts' passkeys on the drive.
    internal sealed class AccountForm : Form
    {
        private readonly ListBox _list;
        private int _choice = -1;

        internal AccountForm(string rpId, string[] accounts)
        {
            Text = "PlugPass";
            Font = new Font("Segoe UI", 9f);
            AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            TopMost = true;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(16);

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.AutoSize = true;
            layout.ColumnCount = 1;
            Label title = new Label();
            title.AutoSize = true;
            title.Font = new Font("Segoe UI Semibold", 11f);
            title.Text = "Which account for " + rpId + "?";
            title.Margin = new Padding(0, 0, 0, 8);
            layout.Controls.Add(title);

            _list = new ListBox();
            _list.Width = 320;
            _list.Height = 120;
            _list.Items.AddRange(accounts);
            _list.SelectedIndex = 0;
            _list.Margin = new Padding(0, 0, 0, 16);
            _list.DoubleClick += delegate { _choice = _list.SelectedIndex; Close(); };
            layout.Controls.Add(_list);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Dock = DockStyle.Fill;
            Button cancel = new Button();
            cancel.Text = "Cancel";
            cancel.MinimumSize = new Size(88, 28);
            cancel.Click += delegate { Close(); };
            Button ok = new Button();
            ok.Text = "Continue";
            ok.MinimumSize = new Size(88, 28);
            ok.Click += delegate { _choice = _list.SelectedIndex; Close(); };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons);
            Controls.Add(layout);
            AcceptButton = ok;
            CancelButton = cancel;
            Shown += delegate { Activate(); _list.Focus(); };
        }

        internal int Choice
        {
            get { return _choice; }
        }
    }

    internal sealed class DialogPrompt : IPinPrompt
    {
        internal DialogPrompt()
        {
            Application.EnableVisualStyles();
        }

        public PinAnswer AskPin(PinQuestion q)
        {
            using (PinForm f = new PinForm(q))
            {
                f.ShowDialog();
                PinAnswer a = new PinAnswer();
                a.Decision = f.Decision;
                a.Pin = f.Decision == Decision.Allow ? f.Pin : null;
                return a;
            }
        }

        public int ChooseAccount(string rpId, string[] accounts)
        {
            using (AccountForm f = new AccountForm(rpId, accounts))
            {
                f.ShowDialog();
                return f.Choice;
            }
        }

        public void Tell(string message)
        {
            MessageBox.Show(message, "PlugPass", MessageBoxButtons.OK, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
        }
    }

#if TESTHOOKS
    // Test build only: answers without windows and logs every question to stderr for the tests.
    // PLUGPASS_TEST_PIN holds the PINs to type, in order, separated by '|'; --test-account N picks an account.
    internal sealed class ScriptedPrompt : IPinPrompt
    {
        private readonly Decision _answer;
        private readonly string[] _pins;
        private readonly int _account;
        private int _next;

        internal ScriptedPrompt(Decision answer, string[] args)
        {
            _answer = answer;
            string pins = Environment.GetEnvironmentVariable("PLUGPASS_TEST_PIN");
            _pins = string.IsNullOrEmpty(pins) ? new string[0] : pins.Split('|');
            string account = Drives.Option(args, "--test-account");
            _account = account == null ? 0 : int.Parse(account);
        }

        public PinAnswer AskPin(PinQuestion q)
        {
            Console.Error.WriteLine("pin:" + (q.IsCreate ? "create" : "get") + ":" + q.RpId + ":" + q.TriesLeft
                + (q.Error == null ? "" : ":" + q.Error));
            PinAnswer a = new PinAnswer();
            a.Decision = _next < _pins.Length ? _answer : Decision.Cancel;
            a.Pin = _next < _pins.Length ? _pins[_next++] : null;
            return a;
        }

        public int ChooseAccount(string rpId, string[] accounts)
        {
            Console.Error.WriteLine("choose:" + rpId + ":" + string.Join(",", accounts));
            return _account;
        }

        public void Tell(string message)
        {
            Console.Error.WriteLine("tell:" + message);
        }
    }
#endif
}
