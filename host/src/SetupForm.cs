using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace PlugPass
{
    // "PlugPass setup": turns a USB flash drive into a PlugPass key. The PIN is typed only here.
    internal sealed class SetupForm : Form
    {
        private readonly ComboBox _drives;
        private readonly TextBox _pin;
        private readonly TextBox _again;
        private readonly Label _message;
        private readonly Button _create;
        private readonly Button _changePin;

        internal SetupForm()
        {
            Text = "PlugPass setup";
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
            layout.ColumnCount = 2;
            layout.Dock = DockStyle.Fill;
            layout.Margin = Padding.Empty;

            Label title = NewLabel("Set up a USB drive as your PlugPass key");
            title.Font = new Font("Segoe UI Semibold", 11f);
            title.Margin = new Padding(0, 0, 0, 16);
            layout.Controls.Add(title);
            layout.SetColumnSpan(title, 2);

            if (!Installer.RunningInstalledCopy)
            {
                // Run from a download folder: offer to install first, so the browser can find PlugPass.
                FlowLayoutPanel installRow = new FlowLayoutPanel();
                installRow.AutoSize = true;
                installRow.WrapContents = false;
                installRow.Margin = new Padding(0, 0, 0, 16);
                Label installText = NewLabel(Installer.IsInstalled
                    ? "Update PlugPass on this PC to this version?"
                    : "PlugPass isn't installed on this PC yet.");
                installText.Anchor = AnchorStyles.Left;
                Button install = new Button();
                install.Text = Installer.IsInstalled ? "Update" : "Install";
                install.AutoSize = true;
                install.MinimumSize = new Size(88, 28);
                install.Anchor = AnchorStyles.Left;
                install.Click += delegate { InstallNow(); };
                installRow.Controls.Add(installText);
                installRow.Controls.Add(install);
                layout.Controls.Add(installRow);
                layout.SetColumnSpan(installRow, 2);
            }

            layout.Controls.Add(NewLabel("USB drive:"));
            FlowLayoutPanel driveRow = new FlowLayoutPanel();
            driveRow.AutoSize = true;
            driveRow.WrapContents = false;
            driveRow.Margin = new Padding(0, 0, 0, 8);
            driveRow.Padding = Padding.Empty;
            _drives = new ComboBox();
            _drives.DropDownStyle = ComboBoxStyle.DropDownList;
            _drives.Width = 220;
            _drives.Margin = new Padding(0, 0, 8, 0);
            _drives.Anchor = AnchorStyles.Left;
            _drives.SelectedIndexChanged += delegate { UpdateState(); };
            _drives.DropDown += delegate { FitDropDown(); };
            Button refresh = new Button();
            refresh.Text = "Refresh";
            refresh.AutoSize = true;
            refresh.MinimumSize = new Size(88, 0);
            refresh.Margin = Padding.Empty;
            refresh.Anchor = AnchorStyles.Left;
            refresh.Click += delegate { LoadDrives(); };
            driveRow.Controls.Add(_drives);
            driveRow.Controls.Add(refresh);
            layout.Controls.Add(driveRow);

            layout.Controls.Add(NewLabel("PIN:"));
            _pin = NewPinBox();
            layout.Controls.Add(_pin);
            layout.Controls.Add(NewLabel("PIN again:"));
            _again = NewPinBox();
            layout.Controls.Add(_again);

            Label hint = NewLabel("At least " + KeyFile.MinPinLength + " characters; letters make it much stronger. "
                + "PlugPass can't recover a forgotten PIN, and " + KeyFile.MaxWrongPins + " wrong PINs in a row erase the key. "
                + "Your password always keeps working. The drive works for Google only on this PC.");
            hint.ForeColor = SystemColors.GrayText;
            hint.Margin = new Padding(0, 4, 0, 0);
            layout.Controls.Add(hint);
            layout.SetColumnSpan(hint, 2);

            // Status line: plain text for information ("plug in a drive"), red only for problems.
            _message = NewLabel("");
            _message.Margin = new Padding(0, 12, 0, 0);
            layout.Controls.Add(_message);
            layout.SetColumnSpan(_message, 2);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Dock = DockStyle.Fill;
            buttons.Margin = new Padding(0, 16, 0, 0);
            buttons.Padding = Padding.Empty;
            Button close = new Button();
            close.Text = "Close";
            close.AutoSize = true;
            close.MinimumSize = new Size(88, 28);
            close.Margin = new Padding(8, 0, 0, 0);
            close.Click += delegate { Close(); };
            _create = new Button();
            _create.Text = "Set up drive";
            _create.AutoSize = true;
            _create.MinimumSize = new Size(88, 28);
            _create.Margin = new Padding(8, 0, 0, 0);
            _create.Click += delegate { CreateKey(); };
            _changePin = new Button();
            _changePin.Text = "Change PIN...";
            _changePin.AutoSize = true;
            _changePin.MinimumSize = new Size(88, 28);
            _changePin.Margin = new Padding(8, 0, 0, 0);
            _changePin.Visible = false;
            _changePin.Click += delegate { ChangePin(); };
            PinForm.SameWidth(_create, close, _changePin);
            buttons.Controls.Add(close);
            buttons.Controls.Add(_create);
            buttons.Controls.Add(_changePin);
            layout.Controls.Add(buttons);
            layout.SetColumnSpan(buttons, 2);

            Controls.Add(layout);
            AcceptButton = _create;
            CancelButton = close;
            LoadDrives();
        }

        private void InstallNow()
        {
            try
            {
                Cursor = Cursors.WaitCursor;
                Installer.Install();
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is InvalidOperationException))
                {
                    throw;
                }
                MessageBox.Show(this, "PlugPass couldn't be installed: " + ex.Message, "PlugPass",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            MessageBox.Show(this, ExtensionSteps(), "PlugPass installed", MessageBoxButtons.OK, MessageBoxIcon.Information);
            System.Diagnostics.Process.Start("explorer.exe", "\"" + Installer.ExtensionDir + "\"");
            System.Diagnostics.Process.Start(Installer.InstalledExe, "setup");
            Close();
        }

        // Browsers only let the Web Store install extensions, so this one step is by hand.
        internal static string ExtensionSteps()
        {
            return "PlugPass is installed. One last step: add the extension to your browser.\n\n"
                + "1. Open brave://extensions (Chrome: chrome://extensions, Edge: edge://extensions).\n"
                + "2. Turn on Developer mode.\n"
                + "3. Click Load unpacked and choose this folder (it opens next):\n   " + Installer.ExtensionDir + "\n\n"
                + "If you loaded PlugPass from another folder before, remove that copy first.";
        }

        private void LoadDrives()
        {
            _drives.Items.Clear();
            foreach (string root in Drives.RemovableRoots())
            {
                _drives.Items.Add(new DriveItem(root));
            }
            if (_drives.Items.Count > 0)
            {
                _drives.SelectedIndex = 0;
            }
            UpdateState();
        }

        private void UpdateState()
        {
            DriveItem d = _drives.SelectedItem as DriveItem;
            bool hasKey = d != null && KeyFile.Exists(d.Root);
            if (d == null)
            {
                ShowMessage("Plug in a USB flash drive, then click Refresh.", false);
            }
            else if (hasKey)
            {
                // Nothing to type here: the PIN boxes are only for a new key.
                ShowMessage("Drive " + d.Root.TrimEnd('\\') + " is already your PlugPass key. There's nothing more to set up. "
                    + "To change its PIN, click Change PIN.", false);
            }
            else
            {
                ShowMessage("", false);
            }
            bool canCreate = d != null && !hasKey;
            _create.Enabled = canCreate;
            _pin.Enabled = canCreate;
            _again.Enabled = canCreate;
            if (!canCreate)
            {
                _pin.Clear();
                _again.Clear();
            }
            _changePin.Visible = hasKey;
            AcceptButton = hasKey ? _changePin : _create;
        }

        private void ChangePin()
        {
            DriveItem d = _drives.SelectedItem as DriveItem;
            if (d == null)
            {
                return;
            }
            using (ChangePinForm f = new ChangePinForm(d.Root))
            {
                f.ShowDialog(this);
            }
            UpdateState();
        }

        private void ShowMessage(string text, bool isProblem)
        {
            _message.Text = text;
            _message.ForeColor = isProblem ? Color.FromArgb(196, 43, 28) : SystemColors.ControlText;
        }

        // The box is narrow; let the open list be as wide as the longest drive name.
        private void FitDropDown()
        {
            int width = _drives.Width;
            foreach (object item in _drives.Items)
            {
                width = Math.Max(width, TextRenderer.MeasureText(item.ToString(), _drives.Font).Width
                    + SystemInformation.VerticalScrollBarWidth);
            }
            _drives.DropDownWidth = width;
        }

        private void CreateKey()
        {
            DriveItem d = _drives.SelectedItem as DriveItem;
            if (d == null)
            {
                return;
            }
            string problem = KeyFile.CheckPin(_pin.Text);
            if (problem == null && _pin.Text != _again.Text)
            {
                problem = "The two PINs don't match.";
            }
            if (problem != null)
            {
                ShowMessage(problem, true);
                return;
            }
            try
            {
                Cursor = Cursors.WaitCursor;
                using (KeyLock held = KeyLock.Acquire(5000))
                {
                    if (held == null)
                    {
                        ShowMessage("A PlugPass PIN window is open. Finish or close it first.", true);
                        return;
                    }
                    KeyFile.Create(d.Root, _pin.Text);
                }
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException))
                {
                    throw;
                }
                ShowMessage("Couldn't set up the drive: " + ex.Message, true);
                return;
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            _pin.Clear();
            _again.Clear();
            MessageBox.Show(this, "Drive " + d.Root + " is now your PlugPass key. Add it to your Google account as a security key or passkey.",
                "PlugPass", MessageBoxButtons.OK, MessageBoxIcon.Information);
            UpdateState();
        }

        private static Label NewLabel(string text)
        {
            Label l = new Label();
            l.AutoSize = true;
            l.MaximumSize = new Size(440, 0);
            l.Text = text;
            l.Margin = new Padding(0, 4, 8, 8);
            return l;
        }

        private static TextBox NewPinBox()
        {
            TextBox t = new TextBox();
            t.UseSystemPasswordChar = true;
            t.MaxLength = KeyFile.MaxPinLength;
            t.Width = 220;
            t.Margin = new Padding(0, 0, 0, 8);
            return t;
        }

        private sealed class DriveItem
        {
            internal readonly string Root;
            private readonly string _label;

            internal DriveItem(string root)
            {
                Root = root;
                string name = "";
                try
                {
                    DriveInfo di = new DriveInfo(root);
                    name = (di.VolumeLabel.Length > 0 ? di.VolumeLabel : "USB drive") + ", "
                        + Math.Round(di.TotalSize / 1073741824.0, 1) + " GB";
                }
                catch (IOException)
                {
                }
                _label = root.TrimEnd('\\') + "  " + name;
            }

            public override string ToString()
            {
                return _label;
            }
        }

        internal static int Run()
        {
            Application.EnableVisualStyles();
            Application.Run(new SetupForm());
            return 0;
        }
    }
}
