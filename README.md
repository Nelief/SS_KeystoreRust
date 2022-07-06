# ss_project
```
Mauro malafronte  M63001104
Daniele Iorio     M63001112
keysstore App for Software Security Exam 
```
USAGE:
    keysstore.exe --cmd <CMD> --pw <PW>
```
OPTIONS:
    -c, --cmd <CMD>          Specifica il comando da eseguire sul keystore
                             new    : crea nuovo keystore [new <password>]
                             add    : aggiunge un nuovo segreto [add <password> <chiave "<segreto1> <segreto2>..." ]
                             list   : mostra segreti [list <password>]
                             reset  : resetta keystore [reset <password>] NON REVERSIBILE
    -h, --help               Print help information
    -k, --key <KEY>          ID/riferimento per il segreto[necessario per comando "Add"]
    -p, --pw <PW>            Password di accesso al keystore
    -s, --secret <SECRET>    Descrizione Segreto[necessario per comando "Add"]

