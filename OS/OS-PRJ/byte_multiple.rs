#[allow(non_upper_case_globals)]
mod byte_constants{
pub const b:f64=1.0;
pub const  Kb:f64=1_000.0;
pub const Mb:f64=1_000_000.0;
pub const  Gb:f64=1000_000_000.0;
pub const  Tb:f64=1000_000_000_000.0;
}
 use byte_constants::*;

fn get_packet_multiple(bytes:f64)->(f64,&'static str){
    let  byte_multiples:f64;
    let  byte_multiples_str:&str;
    if bytes>=Tb{
        byte_multiples=bytes/Tb;
        byte_multiples_str="Tb";
    }
    else if bytes>=Gb{
       byte_multiples=bytes/Gb;
       byte_multiples_str="Gb";
    }
    else if bytes>=Mb{
       byte_multiples=bytes/Mb;
       byte_multiples_str="Mb";
    }
    else if bytes>=Kb{
       byte_multiples=bytes/Kb;
       byte_multiples_str="Kb";
    }
    else {
        byte_multiples=bytes/b;
        byte_multiples_str="b";
    }

    (byte_multiples,byte_multiples_str)
       
}