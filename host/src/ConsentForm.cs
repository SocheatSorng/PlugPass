using System;
using System.Drawing;
using System.Windows.Forms;

namespace PlugPass
{
    // The "touch your key" step: PlugPass never signs anything until the person clicks Allow here.
    // It names the site, so a sign-in started somewhere unexpected stands out.
    internal sealed class ConsentForm : Form
    {
        private Decision _decision = Decision.Cancel;

        internal ConsentForm(bool isCreate, string rpId)
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

            Label title = new Label();
            title.AutoSize = true;
            title.MaximumSize = new Size(420, 0);
            title.Font = new Font("Segoe UI Semibold", 11f);
            title.Text = isCreate ? "Add your PlugPass key to " + rpId + "?" : "Sign in to " + rpId + " with PlugPass?";
            title.Margin = new Padding(0, 0, 0, 8);
            layout.Controls.Add(title);

            Label body = new Label();
            body.AutoSize = true;
            body.MaximumSize = new Size(420, 0);
            body.Text = "Only continue if you started this yourself on " + rpId + ".";
            body.Margin = new Padding(0, 0, 0, 16);
            layout.Controls.Add(body);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Dock = DockStyle.Fill;
            buttons.Margin = new Padding(0);
            Button cancel = NewButton("Cancel", Decision.Cancel);
            Button other = NewButton("Use another key", Decision.Fallback);
            Button allow = NewButton(isCreate ? "Add" : "Sign in", Decision.Allow);
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(other);
            buttons.Controls.Add(allow);
            layout.Controls.Add(buttons);

            Controls.Add(layout);
            AcceptButton = allow;
            CancelButton = cancel;
            Shown += delegate { Activate(); allow.Focus(); };
        }

        internal Decision Decision
        {
            get { return _decision; }
        }

        private Button NewButton(string text, Decision d)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.MinimumSize = new Size(88, 28);
            b.Margin = new Padding(8, 0, 0, 0);
            b.Click += delegate { _decision = d; Close(); };
            return b;
        }
    }

    internal sealed class DialogConsent : IConsent
    {
        public Decision Ask(bool isCreate, string rpId)
        {
            Application.EnableVisualStyles();
            using (ConsentForm f = new ConsentForm(isCreate, rpId))
            {
                f.ShowDialog();
                return f.Decision;
            }
        }
    }

#if TESTHOOKS
    // Test build only: answers without a window and logs each question to stderr for the tests.
    internal sealed class ScriptedConsent : IConsent
    {
        private readonly Decision _answer;

        internal ScriptedConsent(Decision answer)
        {
            _answer = answer;
        }

        public Decision Ask(bool isCreate, string rpId)
        {
            Console.Error.WriteLine("consent:" + (isCreate ? "create" : "get") + ":" + rpId);
            return _answer;
        }
    }
#endif
}
