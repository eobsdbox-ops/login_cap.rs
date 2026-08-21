/*
*  Rust for OpenBSD x86_64
*  login_cap
*/
use std::fs;
use std::fs::OpenOptions;
use std::io::{Error,BufReader,BufRead};
use std::path::Path;
use std::collections::BTreeMap;

// for pledge and unveil
use std::ffi::{c_char,c_int,CString};
use std::ptr;

const PATH_LOGIN_CONF:&str = "/etc/login.conf";
const PATH_LOGIN_CONFD:&str = "/etc/login.conf.d";
const PLEDGE:&str = "stdio rpath";
const OS_ERR:fn()->std::io::Error = Error::last_os_error;

unsafe extern "C" {
	fn pledge(promise:*const c_char, execpromise:*const c_char)->c_int;
	fn unveil(path:*const c_char,prem:*const c_char)->c_int;
}

fn bsd_unveil(path:&str,perm:&str)->Result<(),Error>
{
	let c_path:CString = match CString::new(path) {
		Ok(ok) => ok,
		Err(e) => return Err(Error::other(e)), 
	};
	let c_perm:CString = match CString::new(perm) {
		Ok(ok) => ok,
		Err(e) => return Err(Error::other(e)),
	};
	if unsafe { unveil(c_path.as_ptr(),c_perm.as_ptr())} == -1 {
		return Err(OS_ERR());
	}
	Ok(())
}

fn bsd_pledge(promise:&str,exec:Option<&str>)->Result<(),Error>
{
	let c_promise:CString = match CString::new(promise) {
		Ok(ok) => ok,
		Err(e) => return Err(Error::other(e)), 
	};
	let c_exec:Option<CString> = match exec {
		Some(s) => {
			match CString::new(s) {
				Ok(ok) => Some(ok),
				Err(e) => return Err(Error::other(e)),
			}
		} 
		None => None,
	};
	let c_exec_ptr:*const c_char = match c_exec.as_ref() {
		Some(s) => s.as_ptr() as *const c_char,
		None => ptr::null() as *const c_char,
	};
	if unsafe { pledge(c_promise.as_ptr(),c_exec_ptr)} == -1 {
		return Err(OS_ERR());
	}
	Ok(())
}


#[derive(Debug)]
struct LoginCap {
	// class
	lc_class:String,
	// key,values
	lc_cap:BTreeMap<String,Vec<String>>,
}

impl LoginCap {
	pub fn new(class:&str)->Self
	{
		LoginCap {
			lc_class:class.to_string(),
			lc_cap:BTreeMap::new(),
		}
	}
	
	fn search_file(mut self)->Result<LoginCap,Error>
	{
		// Check /etc/login.conf.d {} is format specifer
		let	classfile = format!("{PATH_LOGIN_CONFD}/{}",&self.lc_class); 
		
		// exist = ok(true) and ok(false) then Err 
		let mut found:bool = if let Ok(true_false) = fs::exists(&classfile) { true_false } else { false }; 
		
		let file = if found {
			// ? just return on error
			OpenOptions::new().read(true).open(classfile)?
		}else {	
			// ? just return on error
			OpenOptions::new().read(true).open(PATH_LOGIN_CONF)?
		};
		
		let mut file_lines = BufReader::new(file).lines();
		
		// found is used for file(above) and for class(below)
		found = false;
		
		while let Some(line) = file_lines.next() {
			
			// Convert line to string
			let mut data = match line {
				Ok(ok)=> ok,
				Err(e)=> return Err(e),
			};
			// Set Class Name
			if !found && data.starts_with(&self.lc_class) {
				
				// verify
				found = self.class_from_str(&data);
				
				// fail verify or data on another line
				if !found || data.contains('\\') { 
					continue; 
				}
				// single line class  
				data = if let Some(s) = data.strip_prefix(&self.lc_class) { 
						s.to_string() 
				} else { 
						return Err(Error::other(format!("bad format: {data}"))); 
				};
				/* fall through */
			}
			// process key value pairs						
			if found {
				match self.process_str(&data) {
					Ok(ok) => if ok { continue; } else { return Ok(self) },
					Err(e) => return Err(Error::other(e)),
				}
			}
		} // WHILE
		Err(Error::other("not found"))
	}
	fn class_from_str(&mut self,data:&str)->bool 
	{
		// take_while is a if in the chain
		let class:String = data.chars().take_while(|a| *a != ':').collect();
				
		// match it exact no default1 
		if self.lc_class == class {
			return true;
		}
		// founded
		false
	}
	fn process_str(&mut self,data:&str)->Result<bool,Error>
	{
		// need a number to state start is unset or set
		let data_len:usize = data.len();
				
		let mut flg:u8 = 0;
		let mut key:&str = "";
		let mut start:usize = data_len;
		let mut end:usize = 0;
		let mut values:Vec<&str> = Vec::new();
				
		// char_indices is recommended for utf8 instead of chars
		for ch in data.char_indices() {
			// looks like a mess but (character,flag) 
			// flg = 1 = getting key
			// flg = 2 = getting value
			// flg = 3 = continuing lines
			match (ch.1,flg) {
				// skip
				('\t',0) => continue,
				// start :
				(':',0) => flg = 1, 	
				// = start value
				('=',1) => {
					key = &data[start..=end];
					flg = 2;
					start = data_len;
				} 
				// end 1 = key only,2 = with values
				(':',1 | 2) => { 
					// set or push value
					if key == "" {
						key = &data[start..=end];
					}else{	
						values.push(&data[start..=end]);
					} 
				}
				// \ another line
				('\\',_) => {
					flg = 3;
					break;
				} 
				// end of line no more data
				('\n',2) => break,	 
				// more then one value a comma seperate list
				(',',2) => { 	
					values.push(&data[start..=end]);
					start = data_len;
				} 
				// key = 1 set start if 0 change end to current index
				('0'..='9' | 'A'..='Z' | 'a'..='z' | '@' | '-' | '/' | ' ',1 | 2) => 
					if start != data_len { end = ch.0 }else{ start = ch.0; end = start }, 
				// good for debugging range above
				(_,_) => { 
					return Err(Error::other(format!("bad format @ {} in {data}",ch.1)));
				}
			}
		}
		// combine duplicate keys mostly tc
		if self.lc_cap.contains_key(key) {
			// update key values
			let prev_vals:&mut Vec<String> = match self.lc_cap.get_mut(key) {
				Some(s) => s,
				None => &mut Vec::new(),
			};
			// Convert Vec<&str> to Vec<String> to make a owner
			let values:Vec<String> = values.iter().map(|s|s.to_string()).collect();
			prev_vals.extend(values);
		}else{
			// new key,new values
			let values = values.iter().map(|s|s.to_string()).collect();
			self.lc_cap.insert(key.to_string(),values);
		}
		// if \ theres more else we are done
		Ok(flg == 3)
	}
	fn style(&self)->Option<String>
	{
		let Some(svec) = self.lc_cap.get("auth") else{ return None; };
		svec.get(0).cloned()
	}
	fn print(&self)
	{
		println!("\n---Class: {}---",self.lc_class);
		for (key,values) in self.lc_cap.iter() {
			let hold = values.join(", ").to_string();
			println!("{:<20} {}",key,hold);
		} 
		if let Some(s) = &self.style() { 
			println!("{:<20} {}","style",s);
		}
		println!("\n---total {}---",self.lc_cap.len());
	}
}

fn main()
{
	if Path::new(PATH_LOGIN_CONFD).exists() {
		if let Err(e) = bsd_unveil(PATH_LOGIN_CONFD,"r"){
			eprintln!("{e}");
		}
	}
	if let Err(e) = bsd_unveil(PATH_LOGIN_CONF,"r"){
		eprintln!("{e}");
	}
	if let Err(e) = bsd_pledge(PLEDGE,None){
		eprintln!("{e}");
	}
	
	let mut lc = match LoginCap::new("staff").search_file(){
		Ok(ok) => ok,
		Err(e) => { eprintln!("{e}");return; }
	};
	lc.print();
	
	println!("following tc");
	
	// finding and remove key tc calling login classes
	while let Some((_ /*void*/,tc_values)) = lc.lc_cap.remove_entry("tc") {
		
		for class in tc_values {
			// find tc values aka inherit class
			println!("\nchecking class: {class}");
			let Ok(lc2) = LoginCap::new(&class).search_file() else{ continue };
			
			for key in lc2.lc_cap.keys() {	
				if lc.lc_cap.contains_key(key) {
					println!("duplicate key skipping: {key}");
					continue;
				}	
				// add inherit key 
				let Some(values) = lc2.lc_cap.get(key) else { continue };
				let newkey:String = key.clone();
				let newvalues:Vec<String> = values.to_vec();
				print!("adding {{\nkey: {newkey}\n");
				for val in newvalues.iter() {
					print!("\tvalue: {val},");
				}
				println!("\n}}");
				lc.lc_cap.insert(newkey,newvalues);
				
			}
		}
	}
	lc.print();
}
