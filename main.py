import argparse
import whois
from nslookup import Nslookup
from googlesearch import search
import requests
import ast
import shodan

class Escaneo:
    def __init__(self, dominio, apikey):
        self.dominio = dominio
        self.apikey = apikey
        return
    
    def nslookupDomain(self):
        self.dns_query = Nslookup(dns_servers=["8.8.8.8"])
        self.ips_record = self.dns_query.dns_lookup(self.dominio)
        self.ip = self.ips_record.answer[0]
        self.soa_record = self.dns_query.soa_lookup(self.dominio)
        self.dnsServer = self.soa_record.answer[0]

    def whoisDomain(self):
        self.w = whois.whois(self.dominio)

    def subdomainsDomain(self):
        self.query = "site:" + self.dominio
        self.subdomainsResult = "".join(str("[-] " + resultado + "\n") for resultado in search(self.query, tld="co.in", num=20, stop=230, pause=2))

    def reverseIpLookupDomain(self):
        url = f"https://sonar.omnisint.io/reverse/{self.ip}"
        try:
            peticion = requests.get(url)
            datos = peticion.text
            lista = ast.literal_eval(datos)
            self.nslookupIpReverse = "".join(str("[-] " + dominio + "\n") for dominio in lista)
            

        except requests.ConnectionError:
            print("Error")

    def shodanSearch(self):
        try:
            if self.apikey is not None:
                # Setup the api
                api = shodan.Shodan(self.apikey)

                # Perform the search
                query = self.ip
                hostinfo = api.host(query)
                if hostinfo is None:
                    print("No information available for that IP.")
                else:
                    # Loop through the matches and print each IP
                    if "last_update" in hostinfo:
                        self.ult_update = hostinfo['last_update']
                    if "city" in hostinfo:
                        self.city = hostinfo['city']
                    if "country_name" in hostinfo:
                        self.country = hostinfo['country_name']
                    if "isp" in hostinfo:
                        self.isp = hostinfo['isp']
                    if "org" in hostinfo:
                        self.org = hostinfo['org']
                    listaDatos = []
                    for data in hostinfo['data']:
                        puerto = ""
                        servicio = ""
                        resumen = ""
                        if "port" in data:
                            puerto = data['port']
                        else:
                            puerto = ""
                        if "product" in data:
                            servicio = data['product']
                        else:
                            servicio = ""
                        if "data" in data:
                            resumen = data['data']
                        else:
                            resumen = ""
                        listaDatos.append(str("\n[******************************************************************]\n" +
                                            "Puerto: " + str(puerto) + " " + str(servicio) + "\n" + str(resumen)))
                    self.scanport = "".join(str(resultado)for resultado in listaDatos)
                    if "vulns" in hostinfo:
                        listaVuln = []
                        for cve in hostinfo['vulns']:
                            listaVuln.append(str("   [*] CVE: " + str(cve) + "\n"))
                        self.vulns = "".join(str(vulne) for vulne in listaVuln)
                    else:
                        self.vulns = "Vulnerabilidades no encontradas con Shodan."
        except shodan.APIError as shodanError:
            if str(shodanError) == "No information available for that IP.":
                print("No information available for that IP.")
                self.scanport = "No hay información."
                self.vulns = "No hay información."
                self.ult_update = "No hay información."
                self.org = "No hay información."
                self.isp = "No hay información."
                self.country = "No hay información."
                self.city = "No hay información."
                pass
            else:
                print("Excepcion " + str(shodanError))



    def __str__(self):
        mensaje = """
                                INFORMACIÓN LOCALIZADA
========================================================================================
[+] NSLOOKUP: El dominio "{}" tiene la IP "{}"
========================================================================================
[+] WHOIS: Información recolecada para el dominio "{}"
{}
========================================================================================
[+]REVERSE IP LOOKUP: Dominios que residen en el mismo servidor {}
{}
========================================================================================
[+] Busqueda de subdominios con GOOGLE:
{}
========================================================================================
[+] Búsqueda del host en SHODAN:
[-] Última actualización de los datos: {}
[-] Datos del proveedor:
    Organización: {}
    ISP: {}
[-] Localización:
    País: {}
    Ciudad: {}
[-] Escaneo de puertos:
{}
[-] Vulnerabilidades encontradas:
{}



        """
        mensajeFinal = mensaje.format(self.dominio,self.ip,self.dominio,self.w,self.ip,self.nslookupIpReverse,self.subdomainsResult,
                                        self.ult_update, self.org, self.isp, self.country, self.city, self.scanport, self.vulns)
        return mensajeFinal

def main():
    try:
        parser = argparse.ArgumentParser(description="Script para la extracción pública de información de un dominio.")
        parser.add_argument("-d","--dominio",help="Parámetro utilizado para introducir el dominio.")
        parser.add_argument("-a","--apikey",help="Parámetro utilizado para especificar la API KEY de Shodan.")
        args = parser.parse_args()
        if args.dominio is None:
            print("""
DNSInfo - Script utilizado para la extracción pública de información relacionada con los nombres de dominio - Versión 1.0

-d --dominio    Parámetro utilizado para introducir el dominio a escanear.
-a --apikey     Parámetro utilizado para especificar la API KEY de Shodan.
-h --help       Parámetro utilizado para ver la descripción del script.

Ejemplos:
- python3 main.py -d dominio.es
- python3 main.py -d dominio.es -a APIKEY
            """)
        else:
            scan = Escaneo(args.dominio, args.apikey)
            scan.nslookupDomain()
            scan.whoisDomain()
            scan.reverseIpLookupDomain()
            scan.subdomainsDomain()
            scan.shodanSearch()
            print(scan)
        
    except Exception as e:
        print("Excepcion " + str(e))

if __name__ == '__main__':
    main()