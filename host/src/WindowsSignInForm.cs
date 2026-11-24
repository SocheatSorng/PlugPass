using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace PlugPass
{
    // "Sign in to Windows with this drive": runs elevated (the setup window starts it with a UAC
    // prompt). Turn on = check the Windows password with Windows, install the sign-in tile, enrol the
    // drive. Turn off = remove this drive's enrolment, and the tile when no drive uses it any more.
    internal sealed class WindowsSignInForm : Form
    {
        private readonly string _root;
        private readonly string _user;
        private readonly Label _status;
        private readonly TextBox _password;
        private readonly Label _message;
        private readonly Button _turnOn;
        private readonly Button _turnOff;
        private readonly Button _turnOffAll;
        private readonly Label _passwordLabel;

        internal WindowsSignInForm(string root, string user)
        {
            _root = root;
            _user = user;
            Text = "PlugPass: Windows sign-in";
            Font = new Font("Segoe UI", 9f);
            AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(16);

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.AutoSize = true;
            layout.ColumnCount = 1;
            layout.Dock = DockStyle.Fill;
            layout.Margin = Padding.Empty;

            Label title = NewLabel(root == null ? "Windows sign-in with PlugPass" : "Sign in to Windows with drive " + root.TrimEnd('\\'));
            title.Font = new Font("Segoe UI Semibold", 11f);
            title.Margin = new Padding(0, 0, 0, 12);
            layout.Controls.Add(title);
            layout.Controls.Add(NewLabel("With this drive plugged in, Windows signs in " + user
                + " without typing, also on the lock screen. Without the drive, your password works as always."));
            Label warn = NewLabel("Anyone who has this drive can sign in to this PC as " + user + ". Keep it safe. "
                + "Lost a drive? Click \"Turn off for all drives\": works without any drive.");
            warn.ForeColor = Color.FromArgb(157, 93, 0);
            layout.Controls.Add(warn);

            _status = NewLabel("");
            _status.Font = new Font("Segoe UI Semibold", 9f);
            _status.Margin = new Padding(0, 4, 0, 12);
            layout.Controls.Add(_status);

            _passwordLabel = NewLabel("Windows password for " + user + ":");
            layout.Controls.Add(_passwordLabel);
            _password = new TextBox();
            _password.UseSystemPasswordChar = true;
            _password.Width = 260;
            _password.Margin = new Padding(0, 0, 0, 8);
            layout.Controls.Add(_password);

            _message = NewLabel("");
            _message.ForeColor = Color.FromArgb(196, 43, 28);
            layout.Controls.Add(_message);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Dock = DockStyle.Fill;
            buttons.Margin = new Padding(0, 12, 0, 0);
            Button close = NewButton("Close");
            close.Click += delegate { Close(); };
            _turnOff = NewButton("Turn off");
            _turnOff.Click += delegate { TurnOff(); };
            _turnOn = NewButton("Turn on");
            _turnOn.Click += delegate { TurnOn(); };
            _turnOffAll = NewButton("Turn off for all drives");
            _turnOffAll.Click += delegate { TurnOffAll(); };
            PinForm.SameWidth(close, _turnOff, _turnOn);
            buttons.Controls.Add(close);
            buttons.Controls.Add(_turnOff);
            buttons.Controls.Add(_turnOn);
            buttons.Controls.Add(_turnOffAll);
            layout.Controls.Add(buttons);

            Controls.Add(layout);
            AcceptButton = _turnOn;
            CancelButton = close;
            Shown += delegate { Activate(); _password.Focus(); };
            UpdateState();
        }

        private void UpdateState()
        {
            bool any = WindowsKey.AnyEnrolments() || TileInstaller.IsInstalled;
            _turnOffAll.Visible = any;
            if (_root == null)
            {
                _status.Text = any ? "Windows sign-in is on for at least one drive." : "Windows sign-in is off.";
                _passwordLabel.Visible = false;
                _password.Visible = false;
                _turnOn.Visible = false;
                _turnOff.Visible = false;
                AcceptButton = null;
                return;
            }
            bool on = WindowsKey.IsEnrolled(_root) && TileInstaller.IsInstalled;
            _status.Text = !on ? "Windows sign-in is off for this drive."
                : WindowsKey.IsRejected(_root)
                    ? "Windows rejected the saved password (did you change it?). Type your current password and click Update."
                    : "Windows sign-in is ON for this drive.";
            _turnOn.Text = on ? "Update" : "Turn on";
            _turnOff.Visible = on;
        }

        // Lost a drive: removes this PC's halves of every enrolment and the sign-in tile.
        private void TurnOffAll()
        {
            if (MessageBox.Show(this, "Turn off Windows sign-in with every PlugPass drive on this PC? "
                    + "A lost drive can't sign in after this. You can turn it on again for a drive you have.",
                    "PlugPass", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK)
            {
                return;
            }
            try
            {
                Cursor = Cursors.WaitCursor;
                WindowsKey.RemoveAll();
                TileInstaller.Uninstall();
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException))
                {
                    throw;
                }
                _message.Text = "Couldn't turn it off: " + ex.Message;
                return;
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            _message.Text = "";
            UpdateState();
        }

        private void TurnOn()
        {
            string password = _password.Text;
            if (!WindowsKey.PasswordIsCorrect(_user, password))
            {
                _message.Text = "That isn't the Windows password for " + _user + ".";
                return;
            }
            try
            {
                Cursor = Cursors.WaitCursor;
                TileInstaller.Install();
                WindowsKey.Enrol(_root, _user, password);
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is System.Security.SecurityException))
                {
                    throw;
                }
                _message.Text = "Couldn't turn it on: " + ex.Message;
                return;
            }
            finally
            {
                Cursor = Cursors.Default;
                _password.Clear();
            }
            _message.Text = "";
            UpdateState();
            MessageBox.Show(this, "Done. To try it, lock your PC (Win+L) with the drive plugged in: it should unlock by itself. "
                + "Your password keeps working in any case.", "PlugPass", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void TurnOff()
        {
            try
            {
                Cursor = Cursors.WaitCursor;
                WindowsKey.Remove(_root);
                if (!WindowsKey.AnyEnrolments())
                {
                    TileInstaller.Uninstall();
                }
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException))
                {
                    throw;
                }
                _message.Text = "Couldn't turn it off: " + ex.Message;
                return;
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            _message.Text = "";
            UpdateState();
        }

        private static Label NewLabel(string text)
        {
            Label l = new Label();
            l.AutoSize = true;
            l.MaximumSize = new Size(420, 0);
            l.Text = text;
            l.Margin = new Padding(0, 0, 0, 8);
            return l;
        }

        private static Button NewButton(string text)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.MinimumSize = new Size(88, 28);
            b.Margin = new Padding(8, 0, 0, 0);
            return b;
        }

        internal static int Run(string root, string user)
        {
            Application.EnableVisualStyles();
            Application.Run(new WindowsSignInForm(root, user));
            return 0;
        }
    }
}
