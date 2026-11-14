Running PscanAV

To prepare the antivirus, open a terminal inside the PscanAV folder and run:

chmod +x start.sh

To start the antivirus, run:

./start.sh ~/Downloads

or

./start.sh ~// to scan all of the files it can reach

Replace "~/Downloads" with the directory you want to scan.

WARNING ⚠️: Do NOT run PscanAV with "sudo". PscanAV is currently in beta, and running it with elevated permissions could expose protected system files to unintended changes.
