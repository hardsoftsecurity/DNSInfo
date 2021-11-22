import argparse
from typing import Text
import whois
from nslookup import Nslookup
from googlesearch import search
import requests
import ast

class Escaneo:
    def __init__(self, dominio):
        self.dominio = dominio
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
        self.listaResultados = []
        self.subdomainsResult = "".join(str("[-] " + resultado + "\n") for resultado in search(self.query, tld="co.in", num=20, stop=230, pause=2))

    def reverseIpLookupDomain(self):
        self.url = f"https://sonar.omnisint.io/reverse/{self.ip}"
        try:
            self.peticion = requests.get(self.url)
            self.datos = self.peticion.text
            self.lista = ast.literal_eval(self.datos)
            self.nuevaLista = []
            self.nslookupIpReverse = "".join(str("[-] " + dominio + "\n") for dominio in self.lista)
            

        except requests.ConnectionError:
            print("Error")

    def __str__(self):
        mensaje = """
                                INFORMACIÓN LOCALIZADA
========================================================================================
+ NSLOOKUP: El dominio "{}" tiene la IP "{}"
========================================================================================
+ WHOIS: Información recolecada para el dominio "{}"
{}
========================================================================================
+ REVERSE IP LOOKUP: Dominios que residen en el mismo servidor {}
{}
========================================================================================
+ Busqueda de subdominios con GOOGLE:
{}
========================================================================================
        """
        mensajeFinal = mensaje.format(self.dominio,self.ip,self.dominio,self.w,self.ip,self.nslookupIpReverse,self.subdomainsResult)
        return mensajeFinal

def main():
    try:
        parser = argparse.ArgumentParser(description="Script para la extracción pública de información de un dominio.")
        parser.add_argument("-d","--dominio",help="Parámetro utilizado para introducir el dominio.")
        args = parser.parse_args()
        scan = Escaneo(args.dominio)
        scan.nslookupDomain()
        scan.whoisDomain()
        scan.reverseIpLookupDomain()
        scan.subdomainsDomain()
        print(scan)
        
    except Exception as e:
        print("Excepcion " + str(e))

if __name__ == '__main__':
    main()