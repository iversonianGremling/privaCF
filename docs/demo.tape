# Render with: vhs docs/demo.tape   (from the privaCF repo root)
# ml-100k (~5 MB) downloads on first run, then caches.
Output "docs/demo.gif"

Set Shell "bash"
Set FontSize 17
Set Width 1180
Set Height 880
Set Padding 22
Set Theme "Catppuccin Mocha"

Hide
Type "cd /home/velasco/workspaces/privaCF/impl" Enter
Type "clear" Enter
Show

Type "# Does privacy-preserving CF actually recommend anything? (E1 gate)" Sleep 600ms Enter
Sleep 700ms
Type "python3 -m privacf.experiment --dataset ml-100k --k 10" Sleep 500ms Enter
Sleep 4500ms
