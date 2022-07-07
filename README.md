# ss_project
```
keysstore App for Software Security Exam 
University Federico II of Naples

Mauro malafronte  M63001104
Daniele Iorio     M63001112

```
```
USAGE:
    keysstore.exe --cmd <CMD> --pw <PW>
```
```
OPTIONS:
    -c, --cmd <CMD>                Specifica il comando da eseguire sul keystore
                                   new    : crea nuovo keystore [new <password>]
                                   add    : aggiunge un nuovo segreto [add <password> <chiave>
                                   "<segreto1> <segreto2>..." ]
                                   list   : mostra segreti [list <password>]
                                   reset  : resetta keystore [reset <password>] NON REVERSIBILE
                                   search    : visualizza il segreto indicato dalla chiave [search
                                   <chiave>]
                                   delete    : elimina il segreto indicato dalla chiave [delete
                                   <chiave>]
    -h, --help                     Print help information
    -k, --key <KEY>                ID/riferimento per il segreto[necessario per comando "Add"]
    -q, --query-key <QUERY_KEY>    Chiave di ricerca [necessaria per comando "Search"]
    -s, --secret <SECRET>          Descrizione Segreto[necessario per comando "Add"]

