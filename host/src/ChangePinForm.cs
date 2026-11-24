using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace PlugPass
{
    // Changes the PIN of a PlugPass drive: current PIN, new PIN twice. A wrong current PIN counts as a
    // wrong try, exactly like signing in (8 in a row erase the key).
    internal sealed class ChangePinForm : Form
    {
        private readonly string _root;
        private readonly TextBox _current;
        private readonly TextBox _pin;
        private readonly TextBox _again;
        private readonly Label _message;

        internal ChangePinForm(string root)
        {
            _root = root;
            Text = "PlugPass";
            Font = new Font("Segoe UI", 9f);
            AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(16);

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.AutoSize = true;
            layout.ColumnCount = 2;
            layout.Dock = DockStyle.Fill;
            layout.Margin = Padding.Empty;

            Label title = NewLabel("Change the PIN of drive " + root.TrimEnd('\\'));
            title.Font = new Font("Segoe UI Semibold", 11f);
            title.Margin = new Padding(0, 0, 0, 16);
            layout.Controls.Add(title);
            layout.SetColumnSpan(title, 2);

            layout.Controls.Add(NewLabel("Current PIN:"));
            _current = NewPinBox();
            layout.Controls.Add(_current);
            layout.Controls.Add(NewLabel("New PIN:"));
            _pin = NewPinBox();
            layout.Controls.Add(_pin);
            layout.Controls.Add(NewLabel("New PIN again:"));
            _again = NewPinBox();
            layout.Controls.Add(_again);

            _message = NewLabel("");
            _message.ForeColor = Color.FromArgb(196, 43, 28);
            _message.Margin = new Padding(0, 4, 0, 0);
            layout.Controls.Add(_message);
            layout.SetColumnSpan(_message, 2);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Dock = DockStyle.Fill;
            buttons.Margin = new Padding(0, 16, 0, 0);
            Button cancel = NewButton("Cancel");
            cancel.Click += delegate { Close(); };
            Button ok = NewButton("Change PIN");
            ok.Click += delegate { Apply(); };
            PinForm.SameWidth(ok, cancel);
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons);
            layout.SetColumnSpan(buttons, 2);

            Controls.Add(layout);
            AcceptButton = ok;
            CancelButton = cancel;
            Shown += delegate { _current.Focus(); };
        }

        private void Apply()
        {
            string problem = KeyFile.CheckPin(_pin.Text);
            if (problem == null && _pin.Text != _again.Text)
            {
                problem = "The two new PINs don't match.";
            }
            if (_current.Text.Length == 0)
            {
                problem = "Type your current PIN.";
            }
            if (problem != null)
            {
                _message.Text = problem;
                return;
            }
            string result;
            bool done = false;
            try
            {
                Cursor = Cursors.WaitCursor;
                using (KeyLock held = KeyLock.Acquire(5000))
                {
                    if (held == null)
                    {
                        _message.Text = "A PlugPass PIN window is open. Finish or close it first.";
                        return;
                    }
                    KeyFile kf = KeyFile.Open(_root);
                    if (kf == null)
                    {
                        _message.Text = "The PlugPass key on this drive can't be read.";
                        return;
                    }
                    switch (kf.Unlock(_current.Text))
                    {
                        case UnlockResult.Ok:
                            kf.ChangePin(_pin.Text);
                            result = null;
                            done = true;
                            break;
                        case UnlockResult.WrongPin:
                            result = "Wrong current PIN. " + kf.TriesLeft + (kf.TriesLeft == 1 ? " try" : " tries")
                                + " left before the key is erased.";
                            break;
                        case UnlockResult.Wiped:
                            result = "Too many wrong PINs: the PlugPass key on this drive was erased. Set the drive up again.";
                            done = true;
                            break;
                        case UnlockResult.Locked:
                            result = "This drive is locked after too many wrong PINs. Set it up again.";
                            break;
                        case UnlockResult.OtherPc:
                            result = "This drive was set up on another PC.";
                            break;
                        default:
                            result = "The PlugPass key on this drive is damaged.";
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException))
                {
                    throw;
                }
                _message.Text = "Couldn't change the PIN: " + ex.Message;
                return;
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            _current.Clear();
            if (!done)
            {
                _message.Text = result;
                _current.Focus();
                return;
            }
            _pin.Clear();
            _again.Clear();
            MessageBox.Show(this, result ?? "PIN changed. Use the new PIN from now on.", "PlugPass",
                MessageBoxButtons.OK, result == null ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            Close();
        }

        private static Label NewLabel(string text)
        {
            Label l = new Label();
            l.AutoSize = true;
            l.MaximumSize = new Size(380, 0);
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

        private static Button NewButton(string text)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.MinimumSize = new Size(88, 28);
            b.Margin = new Padding(8, 0, 0, 0);
            return b;
        }
    }
}
