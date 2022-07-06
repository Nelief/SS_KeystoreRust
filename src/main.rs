mod function;
use function::{verify_password_hash,create_crypto_key,process_secret,make_secret_line,print_secret,make_keychain_cofing};

use clap::{Parser,ArgEnum};

use std::fs::{File,remove_file};
use std::io::{BufReader, BufRead, Error};
use std::path::Path;

//Enum della lista dei comandi legali sul sistema 
#[derive(Debug,PartialEq,Clone,ArgEnum)]
enum Cmd{
    List,
    Add,
    New,
    Reset,
}

//Struct di parsing per gli input CLI
//cmd e pw risultano obbligatori, key e secret diventano obbligatori nel caso di comando "add"
#[derive(Parser, Debug)]
#[clap(disable_version_flag(true))]
struct Args {
    #[clap(long,id="cmd",short = 'c',value_parser,arg_enum,hide_possible_values(true),help ="Specifica il comando da eseguire sul keystore\n\x1b[92mnew\x1b[0m    : crea nuovo keystore [new <password>]\n\x1b[92madd\x1b[0m    : aggiunge un nuovo segreto [add <password> <chiave>  \"<segreto1> <segreto2>...\" ]\n\x1b[92mlist\x1b[0m   : mostra segreti [list <password>]\n\x1b[92mreset\x1b[0m  : resetta keystore [reset <password>] NON REVERSIBILE\n"                                  )]
    cmd : Cmd,

    #[clap(long,short = 'p',value_parser,help="Password di accesso al keystore")]
    pw : String,

    #[clap(long,short = 'k',value_parser,required_if_eq("cmd","add"),default_value="",help =r#"ID/riferimento per il segreto[necessario per comando "Add"]"#, hide_default_value(true))]
    key : String,
    
    #[clap(long,short = 's',value_parser,required_if_eq("cmd","add"),default_value="",help =r#"Descrizione Segreto[necessario per comando "Add"]"#,hide_default_value(true))]
    secret : String, 
}

//nomi dei file nascosti usati dal sistema 
static PATH : &str = "file.txt";
static CPATH : &str = "cfg.txt";

fn main() -> Result<(), Error> {
    let args = Args::parse();
    
    match args.cmd {
        Cmd::New => {
            if Path::new(PATH).exists() {
                println!("keystore already exists, please reset before configuring a new one!");
            }else{
                let password = args.pw;
                if  password.len() > 7 {
                    make_keychain_cofing(password, PATH, CPATH);
                } else {
                    println!("Error: password is too short ( 8 char min)!");
                }
            }
        }
        Cmd::List => {
            let password = args.pw.as_str();
            if verify_password_hash(password,CPATH){
                let key = create_crypto_key(password);
                println!("printing...");
                let f = File::open(PATH)?;
                let reader = BufReader::new(f);

                for line in reader.lines(){
                    match line{
                        Ok(line) => {
                            if line.len()>0 {
                                process_secret(line, key);
                            }
                        }     
                        Err(e) => println!("Errorr : {}",e),
                    }        
                }  
            } else{
                println!("Wrong password");
            }
        }
        Cmd::Add => {
            let password = args.pw.as_str();
            if verify_password_hash(password,CPATH){
                let key = create_crypto_key(password);
                let secret_name = args.key;
                let secret_value = args.secret;
                if secret_name.len() <=20 && secret_value.len() <=100{
                    let secret = make_secret_line(secret_name, secret_value);
                    print_secret(PATH, secret, key);
                }else{
                    println!("Error: key or secret are too long (20/100 char limit)!");
                }
            } else{
                println!("Wrong password");
            }
        }
        Cmd::Reset => {
            let password = args.pw.as_str();
            if verify_password_hash(password,CPATH){
                remove_file(PATH)?;
                remove_file(CPATH)?;
                print!("keystore reset complete...");
            }
        }
    }
    Ok(())
}
