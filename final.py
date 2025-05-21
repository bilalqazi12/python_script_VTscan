import csv
import json
# import time
import urllib.request

VT_API_KEY = "9754b35249afc27389aab432fff85d1d4e25dd82cc75056f4bc839e062a2a2cc"     # VT API Key

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"                    # API URL

HEADERS = {
    "x-apikey" : VT_API_KEY
}

def query_ip(ip):                                                       #Function for Scanning the IP's
    url = VT_API_URL.format(ip)
    req = urllib.request.Request(url, headers=HEADERS)

    try:
        with urllib.request.urlopen(req) as response:                      #JSON           
            data = json.load(response)                                      
            stats = data['data']['attributes']['last_analysis_stats']       #JSON Parse or Convert itn to python Dictionary  
            print(f"\n IP: {ip}")
            print(f" Harmless:   {stats['harmless']}")              #JSON result in the python dictionary
            print(f" Suspicious: {stats['suspicious']}")
            print(f" Malicious:  {stats['malicious']}")

            vt_url = f"https://www.virustotal.com/gui/ip-address/{ip}"    # Print URL to manually view in browser
            print(f" View in browser: {vt_url}")
            print("-" * 50)

    except urllib.error.HTTPError as e:
        error_message = e.read().decode()
        print(f" HTTP error for {ip}: {e.code} - {e.reason}")
        print("Details:", error_message)
    except Exception as e:
        print(f" Failed to scan {ip}: {e}")

def main():
    with open("data.csv") as f :
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip")
            if ip:
                query_ip(ip)
                #time.sleep(10) 
             
if __name__ == "__main__":
    main()