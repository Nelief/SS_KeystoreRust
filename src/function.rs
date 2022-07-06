use std::fs::OpenOptions;
use std::io::{Write, Read};
use std::str; 

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

    print!("Segreto inserito nel portachiavi!");
}

///Input : String : master password per l' accesso al keystore , &str : Path al file dei segreti , &str : Path al file di configurazione
/// 
///la fn genera la hash della password ricevuta chiamando bycrypt.hash() e procede a inizializzare e creare 2 file nascosti (FILE_ATTRIBUTE_HIDDEN di windows), termina scrivendo la hash sul file di configurazione 
pub fn make_keychain_cofing(password : String, file_path: &str, config_path: &str){
    println!("creazione nuovo keychain");
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