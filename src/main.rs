use libsm::sm2:: {
    signature::{SigCtx, Signature,Pubkey,Seckey},

};
use std::time::Instant;
use std::io::prelude::*;
use rand::OsRng;
use secp256k1::{Secp256k1, Message};

fn sign(ctx: &SigCtx,pk:&Pubkey, sk:&Seckey,msg:&[u8]) -> Signature {
    ctx.sign(msg, sk, pk)
}

fn verify(ctx: &SigCtx,msg:&[u8] ,pk:&Pubkey, sig:&Signature) -> bool {
    ctx.verify(msg, pk,sig)
}

fn main() {
    
    let count = {
        let mut file = std::fs::File::open("count.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        contents.trim().parse::<usize>().unwrap()
    };

    let msg = ['0' as u8;32];
    let mut now = Instant::now();

    if count % 2 == 0 {
        let mut sigs = Vec::new();
        sigs.reserve(count);
        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair();
        for i in 0..count {
            let mut msg = msg.clone();
            let i = i%32;
            msg[i] = msg[i].wrapping_add(1);
            let signature = sign(&ctx,&pk,&sk,&msg);
            sigs.push((msg,signature));
        }
        println!("sm2 time {:?}",now.elapsed());
        now = Instant::now();
        for (msg,sig) in sigs {
            verify(&ctx,&msg,&pk,&sig);
        }
    } else {
        let mut sigs = Vec::new();
        sigs.reserve(count);
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        for i in 0..count {
            let mut msg = msg.clone();
            let i = i%32;
            msg[i] = msg[i].wrapping_add(1);
            let message = Message::from_slice(&msg).expect("32 bytes");
            let sig = secp.sign(&message, &secret_key);
            sigs.push((message,sig));
        }
        println!("secp256 time {:?}",now.elapsed());
        now = Instant::now();
        for (msg,sig) in sigs {
            secp.verify(&msg, &sig, &public_key);
        }
    }
    println!("time {:?}",now.elapsed());
}
