# Recovery: if the PlugPass sign-in tile ever gets in the way

PlugPass never hides Windows' own sign-in: with or without the drive, **"Sign-in options" → password**
should always be there. These steps are for the unlikely case that the sign-in screen itself misbehaves
(for example, it doesn't appear or keeps restarting).

Print this page or keep it on your phone. You need your Windows password, not the drive.

## 1. Easiest: pull the drive and use your password

Unplug the PlugPass drive, restart, and sign in with your password. Without the drive the tile shows
nothing. Then open PlugPass → **Windows sign-in...** → **Turn off for all drives**.

## 2. If the sign-in screen doesn't work at all: remove the tile from Windows Recovery

1. On the sign-in screen, hold **Shift** and click **Power → Restart**. (If Windows doesn't start at all,
   it opens Recovery by itself after two failed starts.)
2. **Troubleshoot → Advanced options → Command Prompt**.
3. Find your Windows drive (in Recovery it is often `D:`, not `C:`):

   ```
   dir C:\Windows
   dir D:\Windows
   ```

4. Rename the tile so Windows can't load it (use the letter you found; `D:` shown here):

   ```
   ren "D:\Program Files\PlugPass\PlugPassCredProv.dll" PlugPassCredProv.disabled
   ```

5. Type `exit`, choose **Continue**. Windows starts without the PlugPass tile; sign in with your
   password, then open PlugPass → **Windows sign-in...** → **Turn off for all drives** to clean up.

## 3. Last resort: system restore

**Troubleshoot → Advanced options → System Restore**, and pick a restore point from before Windows
sign-in was turned on (Windows names automatic ones "Scheduled Checkpoint"). It may also undo other
programs installed after it.

## What PlugPass changed (for reference)

- `C:\Program Files\PlugPass\PlugPassCredProv.dll`, the tile (and `PlugPass.exe`, the admin copy of the app)
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{9170534E-8919-480A-A99A-4EF4979FE7A3}`
- `HKLM\SOFTWARE\Classes\CLSID\{9170534E-8919-480A-A99A-4EF4979FE7A3}`
- `HKLM\SOFTWARE\PlugPass\SignIn`, your encrypted password, one value per drive (only SYSTEM and
  Administrators can read it)

If Windows rejected the saved password (you changed it), the tile stops on its own; open PlugPass →
**Windows sign-in...**, type the new password and click **Update**.
