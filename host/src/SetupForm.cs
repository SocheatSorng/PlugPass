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

            Label title = NewLabel("Set up a USB drive as your PlugPass key");
            title.Font = new Font("Segoe UI Semibold", 11f);
            layout.Controls.Add(title);
            layout.SetColumnSpan(title, 2);

            layout.Controls.Add(NewLabel("USB drive:"));
            FlowLayoutPanel driveRow = new FlowLayoutPanel();
            driveRow.AutoSize = true;
            driveRow.Margin = new Padding(0, 0, 0, 8);
            _drives = new ComboBox();
            _drives.DropDownStyle = ComboBoxStyle.DropDownList;
            _drives.Width = 220;
            _drives.SelectedIndexChanged += delegate { UpdateState(); };
            Button refresh = new Button();
            refresh.Text = "Refresh";
            refresh.AutoSize = true;
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
            layout.Controls.Add(hint);
            layout.SetColumnSpan(hint, 2);

            _message = NewLabel("");
            _message.ForeColor = Color.FromArgb(196, 43, 28);
            layout.Controls.Add(_message);
            layout.SetColumnSpan(_message, 2);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Dock = DockStyle.Fill;
            Button close = new Button();
            close.Text = "Close";
            close.MinimumSize = new Size(88, 28);
            close.Click += delegate { Close(); };
            _create = new Button();
            _create.Text = "Set up drive";
            _create.AutoSize = true;
            _create.MinimumSize = new Size(88, 28);
            _create.Click += delegate { CreateKey(); };
            buttons.Controls.Add(close);
            buttons.Controls.Add(_create);
            layout.Controls.Add(buttons);
            layout.SetColumnSpan(buttons, 2);

            Controls.Add(layout);
            AcceptButton = _create;
            CancelButton = close;
            LoadDrives();
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
            if (d == null)
            {
                _message.Text = "Plug in a USB flash drive, then click Refresh.";
                _create.Enabled = false;
            }
            else if (KeyFile.Exists(d.Root))
            {
                _message.Text = "This drive already has a PlugPass key.";
                _create.Enabled = false;
            }
            else
            {
                _message.Text = "";
                _create.Enabled = true;
            }
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
                _message.Text = problem;
                return;
            }
            try
            {
                Cursor = Cursors.WaitCursor;
                KeyFile.Create(d.Root, _pin.Text);
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException))
                {
                    throw;
                }
                _message.Text = "Couldn't set up the drive: " + ex.Message;
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
