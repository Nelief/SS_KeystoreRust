use std::fs::{OpenOptions,remove_file};
use std::io::{Write, Read,BufReader,BufRead,self};
use std::str; 
use std::collections::HashMap;

use pwhash::bcrypt::{verify,hash};
use rand::{RngCore, SeedableRng};

use aes_prng::AesRng;
use hex_literal::hex;
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode,Ecb};

use std::fs::{File};

use std::os::windows::fs::OpenOptionsExt;


type Aes128Ecb = Ecb<Aes128, Pkcs7>;

static HIDDEN_FILE : u32 = 2;

///input  : &str user input master password 
/// 
///output : boolean, true if the password match
/// 
///carica il file di configurazione ed estrae la hash, chiamando la funzione verify per verificare che le password combacino
pub fn verify_password_hash(password : &str, hash_path : &str) -> bool{

    let mut f = File::open(hash_path).unwrap();
    let mut hash = String::new();
    f.read_to_string(&mut hash).unwrap();

    verify(password,&hash)
}

///input  : &str user input master password 
/// 
///output : pseudo-random encryption key generated from password
/// 
///genera una chiave di encription a partire dalla stringa data ( usata come seed) sfruttando il generatore di numeri casuali della libreria AesRng
pub fn create_crypto_key(password : &str) -> [u8;16]{
    let seed = &password.parse::<u64>().unwrap(); 
    let mut rng = AesRng::seed_from_u64(*seed); 
    let mut bytes = [0u8;16];
    rng.fill_bytes(&mut bytes);
    bytes
}

///input  : Vec<u8> contenente i byte da decrittare , [u8,16] con la chiave di encryption/decryption
/// 
///output : un vettore di u8 con il testo in chiaro 
/// 
///istanzia iv e chiper per poi invocare la decrypt, la separazione dei 2 metodi e necessarie per i limiti sulla lifeline delle variabili di rust 
pub fn decrypt_secret(buffer : &mut Vec<u8>,key : [u8;16])-> &[u8]{
    let iv = hex!("");
    let cipher = Aes128Ecb::new_from_slices(&key, &iv).unwrap();
    cipher.decrypt(buffer).unwrap()
}

/// input  : String, linea estratta dal file criptato , [u8,16] la chiave di encryption 
/// 
/// la fn non ha output ma stampa a video il segreto decriptato  
/// 
/// istanzia un vec<u8> nel quale scarica la linea (convertita tramite hex::decode) 
pub fn process_secret(line : String, key : [u8;16]){
    let mut u8buf = hex::decode(line).unwrap(); 
    let decrypted_text = decrypt_secret(&mut u8buf, key);
    println!("{}", str::from_utf8(decrypted_text).unwrap());
}

///compone il segreto da salvare su file concatenando key e secret 
pub fn make_secret_line(key : String , secret : String ) -> String{
    let key = key;
    let secret = secret;
    let fullstring = key + "|" +&secret;
    fullstring
}

///input : String segreto da criptare , [u8,16] chiare di encryption
/// 
///output : codifica hex del segreto criptato
/// 
///prepara un buffer per contenere la stringa criptata (u8,128) e l' iv per l' encryption, istanzia il chiper con la chiave data in input e procede alla generazione del testo cifrato 
pub fn process_encrypted_secret(secret : String, key : [u8;16]) -> String{

    let u8secret = secret.as_bytes(); //String -> byte
    let size = u8secret.len(); //estrae la size del buffer
    let mut buffer = [0u8;128]; // crea buffer d' appoggio
    buffer[..size].copy_from_slice(u8secret); //popola il buffer d'appoggio

    let iv = hex!("");
    let cipher = Aes128Ecb::new_from_slices(&key, &iv).unwrap();

    let ciphertext = cipher.encrypt(&mut buffer, size).unwrap();

    hex::encode(ciphertext)
}

///input   : &str Path al file dei segreti , String : segreto da criptare  , [u8,16] : chiave di encryption 
/// 
///la fn procede aprendo il file dei segreti, e scrivendoci sopra in append il risultato della chiamata a "process_encrypted_secret"
pub fn print_secret(path : &str, secret : String, key : [u8;16]){
    let mut output = OpenOptions::new()
    .write(true)
    .append(true)
    .open(path)
    .unwrap();

    writeln!(output,"{}",process_encrypted_secret(secret, key)).unwrap();  
}

///Input : String : master password per l' accesso al keystore , &str : Path al file dei segreti , &str : Path al file di configurazione
/// 
///la fn genera la hash della password ricevuta chiamando bycrypt.hash() e procede a inizializzare e creare 2 file nascosti (FILE_ATTRIBUTE_HIDDEN di windows), termina scrivendo la hash sul file di configurazione 
pub fn make_keychain_cofing(password : String, file_path: &str, config_path: &str){
    println!("creazione nuovo keystore");
    //estrarre variabili arg
    let password = password.as_str();
    let pw_hash = hash(password).unwrap();
    

    let mut cfg_file = OpenOptions::new()
    .write(true)
    .create(true)
    .append(true)
    .attributes(HIDDEN_FILE) 
    .open(config_path)
    .unwrap();

    write!(cfg_file,"{}",pw_hash).unwrap();
   
    OpenOptions::new()
    .create(true)
    .append(true)
    .attributes(HIDDEN_FILE)
    .open(file_path)
    .unwrap();

}

///stampa e richiede la password master da stdin
pub fn get_password () -> String{

    //richiesta pw 
    print!("Inserire password master  >> ");
    let _ = io::stdout().flush();

    //password from stdinput
    let in_reader = BufReader::new(io::stdin());
    in_reader.lines().next().unwrap().unwrap()
}

///Estrae il segreto da "line", lo decritta, ed inserisce nella hashmap
pub fn to_map(secret_map: & mut HashMap<String, String>, line : String, key : [u8;16]){
    let mut u8buf = hex::decode(line).unwrap(); 
    let iv = hex!("");

    let cipher = Aes128Ecb::new_from_slices(&key, &iv).unwrap();
    
    let decrypted_text = cipher.decrypt(&mut u8buf).unwrap();
    let text = str::from_utf8(decrypted_text).unwrap().to_owned();

    let v : Vec<&str> = text.split('|').collect();
    let key = v[0].clone().to_owned();
    let secret = v[1].clone().to_owned();

    secret_map.insert(key.clone().to_owned(),secret.clone().to_owned());
}

///rigenera un nuovo keystore per l' update 
pub fn reset_secret(path : &str){
    remove_file(path).unwrap();

    _ = OpenOptions::new()
    .create(true)
    .write(true)
    .open(path)
    .unwrap();
}

///processa path e password per decriptare il keystore e prepara la hash per la ricerca 
pub fn search_key(query_key : String, path : &str, password : &str){
    let  secret_map = generate_hashmap(password, path);
    
    if secret_map.contains_key(&query_key) {
        let (hkey,hval) = secret_map.get_key_value(&query_key).unwrap();
        print!("chiave : {} | Segreto : {}" ,hkey,hval);
    } else {
        println!("Chiave non trovata!");
    }  
}


///cancella la keypair indicata da query_key se presente ed aggiorna il keystore
pub fn delete_keypair(password : &str, query_key : String, path : &str){

    let mut secret_map =  generate_hashmap(password, path);

    if secret_map.contains_key(&query_key) {
        
        secret_map.remove(&query_key);

        let mut secret_vec = Vec::new();                
        for k in secret_map.keys(){
            let (key,value) = secret_map.get_key_value(k).unwrap();
            secret_vec.push(make_secret_line(key.to_string(), value.to_string()));
        }    

        let key = create_crypto_key(password);

        let mut i = 0;
        for s in secret_vec{
            if i == 0{
                reset_secret(path); 
                i=i+1;
            } 
            print_secret(path, s, key)
            
        }
       
       print!("Chiave rimossa con successo!");
    } else {
        println!("Chiave non trovata!")
    }
}

///genera una hashmap a partire dal file keystore
pub fn generate_hashmap(password : &str, path : &str) -> HashMap<String,String>{
    let key = create_crypto_key(password);
    let f = File::open(path).unwrap();
    let reader = BufReader::new(f);

    let mut secret_map : HashMap<String,String> = HashMap::new();

    for line in reader.lines(){
        match line{
            Ok(line) => {
                if line.len()>0 {
                    to_map(&mut secret_map, line, key);   
                }
            }     
            Err(e) => println!("Errorr : {}",e),
        }        
    }
    secret_map
}

///aggiunge un segreto univoco al keystore cifrandolo con la password 
pub fn add_secret(password: &str, key : String , secret : String,path : &str){
    let ckey = create_crypto_key(password);
    let secret_name = key;
    let secret_value = secret;
    if secret_name.len() <=20 && secret_value.len() <=100{
        let secret = make_secret_line(secret_name, secret_value);
        print_secret(path, secret, ckey);
        print!("Segreto inserito nel portachiavi!");
    }else{
        println!("Error: chiave o segreto troppo lunghi (20/100 char limit)!");
    }
}

///verifica che la chiave non sia gia presente nel keystore
pub fn verify_key(key : &String, path : &str, password : &str) -> bool{
    let  secret_map = generate_hashmap(password, path);
    
    if secret_map.contains_key(key) {
        true
    } else {
        false
    }  
}

///stampa a video la lista dei segreti nel keystore
pub fn list_secrets(password : &str, path : &str){
    let key = create_crypto_key(password);
    let f = File::open(path).unwrap();
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
}