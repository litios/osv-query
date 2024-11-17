mod osv;
use std::env;

fn send_request(url: &str, body: osv::Request) -> Result<osv::Response, reqwest::Error> {
    let client = reqwest::blocking::Client::new();

    let res = client.post(url)
    .body(serde_json::to_string(&body).unwrap())
    .send().unwrap();
    
    Ok(res.json::<osv::Response>().unwrap())
}

fn analyze_response(response: osv::Response) {
    for vuln in response.vulns.iter() {
        let mut found = false;
        for cve in vuln.aliases.iter() {
            if cve.contains("CVE-") {
                println!("{}::{}", vuln.id, cve);
                found = true;
            }
        }
        if !found {
            continue;
        }

        for affected in vuln.affected.iter() {
            for range in affected.ranges.iter() {
                println!(" Fixed information type: {}", range.type_field);
                for event in range.events.iter() {
                    if event.fixed != None {
                        println!("  * {} # Fixed in {}", affected.package.name, event.fixed.clone().unwrap());

                    } else if event.introduced != None {
                        println!("  * {} # Introduced in {}", affected.package.name, event.introduced.clone().unwrap());
                    }
                }
            }
        }
    }
}
 
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: {} package version ecosystem", args[0]);
        return;
    }
    let package = args[1].to_string();
    let version = args[2].to_string();
    let ecosytem = args[3].to_string();

    let request: osv::Request = osv::Request{
        package: osv::Package{
            name: package,
            ecosystem: ecosytem,
            purl: "".to_string()
        },
        commit: "".to_string(),
        version: version,
        next_page_token: "".to_string()
    };

    let response: osv::Response = send_request("https://api.osv.dev/v1/query", request)
    .expect("Error when requesting");
    analyze_response(response);
}
