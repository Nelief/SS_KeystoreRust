mod function;
use function::*;

use clap::{Parser,ArgEnum};
use std::fs::remove_file;
use std::io::Error;
use std::path::Path;
use std::str;

//Enum della lista dei comandi legali sul sistema 
#[derive(Debug,PartialEq,Clone,ArgEnum)]
enum Cmd{
    List,
    Add,
    New,
    Reset,
    Search,
    Delete
}

//Struct di parsing per gli input CLI
//cmd e pw risultano obbligatori, key e secret diventano obbligatori nel caso di comando "add"
#[derive(Parser, Debug)]
#[clap(disable_version_flag(true))]
struct Args {
    #[clap(long,id="cmd",short = 'c',value_parser,arg_enum,hide_possible_values(true),help ="Specifica il comando da eseguire sul keystore\n\x1b[92mnew\x1b[0m    : crea nuovo keystore [new <password>]\n\x1b[92madd\x1b[0m    : aggiunge un nuovo segreto [add <password> <chiave>  \"<segreto1> <segreto2>...\" ]\n\x1b[92mlist\x1b[0m   : mostra segreti [list <password>]\n\x1b[92mreset\x1b[0m  : resetta keystore [reset <password>] NON REVERSIBILE\n\x1b[92msearch\x1b[0m    : visualizza il segreto indicato dalla chiave [search <chiave>]\n\x1b[92mdelete\x1b[0m    : elimina il segreto indicato dalla chiave [delete <chiave>]\n"                                  )]
    cmd : Cmd,

    #[clap(long,short = 'k',value_parser,required_if_eq("cmd","add"),default_value="",help =r#"ID/riferimento per il segreto[necessario per comando "Add"]"#, hide_default_value(true))]
    key : String,
    
    #[clap(long,short = 's',value_parser,required_if_eq("cmd","add"),default_value="",help =r#"Descrizione Segreto[necessario per comando "Add"]"#,hide_default_value(true))]
    secret : String, 

    #[clap(long,short = 'q',value_parser,required_if_eq_any(&[("cmd","search"),("cmd","delete")]),default_value="",help =r#"Chiave di ricerca [necessaria per comando "Search"]"#,hide_default_value(true))]
    query_key : String, 
}

//nomi dei file nascosti usati dal sistema 
static PATH : &str = "keystore.txt";
static CPATH : &str = "cfg.txt";

fn main() -> Result<(), Error> {
    let args = Args::parse();

    
    let input_password = get_password();

    match args.cmd {
        Cmd::New => {
            if Path::new(PATH).exists() {
                println!("Keystore già esistente!\n");
            }else{
                if  input_password.len() > 7 {
                    make_keystore_cofing(input_password, PATH, CPATH);
                } else {
                    println!("Error: password troppo corta ( 8 char min )!\n");
                }
            }
        }
        Cmd::List => {
            if Path::new(PATH).exists() {
                let password = input_password.as_str();
                if verify_password_hash(password,CPATH){
                    list_secrets(password, PATH);
                } else{
                    println!("Password errata!\n");
                }
            }else{
                println!(r#"Keystore inesistente (inizializzare con "new")\n"#);
            }
        }
        Cmd::Add => {
            if Path::new(PATH).exists() {
                let password = input_password.as_str();
                if verify_password_hash(password,CPATH){
                    if !verify_key(&args.key, PATH, password){
                        add_secret(password, args.key, args.secret, PATH);
                    }else{
                        println!("Chiave già presente!\n");
                    }
                } else{
                    println!("Password errata!\n");
                }
            }else{
                println!(r#"Keystore inesistente (inizializzare con "new")\n"#);
            }
            
        }
        Cmd::Reset => {
            if Path::new(PATH).exists() {
                    let password = input_password.as_str();
                if verify_password_hash(password,CPATH){
                    remove_file(PATH)?;
                    remove_file(CPATH)?;
                    print!("Keystore cancellato con successo!\n");
                }
            }else{
                println!(r#"Keystore inesistente (inizializzare con "new")\n"#);
            }
            
        }
        Cmd::Search =>{
            if Path::new(PATH).exists() {
                    let password = input_password.as_str();
                if verify_password_hash(password,CPATH){
                    search_key(args.query_key, PATH, password);
                } else{
                    println!("Password errata!\n");
                }
            }else{
                println!(r#"Keystore inesistente (inizializzare con "new")\n"#);
            }
            
        } 
        Cmd::Delete => {
            if Path::new(PATH).exists() {
                    let password = input_password.as_str();
                if verify_password_hash(password,CPATH){
                    delete_keypair(password, args.query_key, PATH)
                } else{
                    println!("Password errata!\n");
                }
            }else{
                println!(r#"Keystore inesistente (inizializzare con "new")\n"#);
            }
            
        }
    }
    Ok(())
}

