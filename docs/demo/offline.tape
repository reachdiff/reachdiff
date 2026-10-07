# reachdiff offline demo. Record from the repository root with reachdiff installed in .venv:
#   vhs docs/demo/offline.tape
# Synthetic plan, no workspace, nothing identifying.
Output docs/demo/offline.gif

Set Shell "bash"
Set FontSize 13
Set Width 1820
Set Height 430
Set Padding 24
Set TypingSpeed 35ms
Set Theme "Builtin Dark"

Hide
Type `export PATH="$PWD/.venv/bin:$PATH" PS1='$ ' && clear`
Enter
Show

Sleep 600ms
Type "reachdiff plan --tfplan examples/schema-grant.plan.json --offline"
Sleep 700ms
Enter
Sleep 9s
