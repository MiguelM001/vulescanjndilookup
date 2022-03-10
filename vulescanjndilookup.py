#!/usr/bin/env python
#
# -*- coding: utf-8 -*- 
#
# TITULO: HERRAMIENTA AUTOMATIZADA DE DETECCION DEL ARCHIVO JndiLookup.class DE LA VULNERABILIDAD CVE-2021-44228
#
# SUSCERTE: VENCERT
# DIRECCION DEL VENCERT
# AUTOR: MIGUEL MARQUEZ 
# CARACAS, MARZO DEL 2022
#
# vulescanjndilookup.py V 1.0
#
#
import re
import os
import sys
from zipfile import *

#============================IMPRIMIR============================

def imprimirAyuda():

	print( "\nEscaner de CVE-2021-44228\n\n"+

     	  	 "Ejemplo de uso:\n\n"+
      
      	  	 "\tpython3 vulescanjndilookup.py -d /directorio/subdirectorio/aplicacionjava/\n\n"+
         
       	  	"Comandos:\n\n"+
         
       	  	"-d --directorio\tIntroduzca la ruta del directorio de la aplicacion java\n"+
        	"-h --ayuda\tComando que despliega la ayuda\n"
         
		 )

#============================ESCANER=============================

def escaner(ruta):

	print("\n\t\t\t\t\t\tvulescanjndilookup.py V 1.0\n\n")

	print("La ruta introducida es: "+ruta)

	print("\nEscaneando . . .")

	primerIndicador= True
	segundoIndicador= True

	#patron = re.match('log4j-core\-(.*)\.jar',xJar)

	for actualDir, subDir, archivos in os.walk(ruta):#establecer la ruta
		for xJar in archivos:
			aux= xJar[len(xJar)-4:len(xJar)]
			if '.JAR' == aux.upper():
			
				log4jCore= re.match('log4j-core\-(.*)\.jar',xJar)

				if log4jCore:
					segundoIndicador= False
					rutaAbsoluta= actualDir+'/'+log4jCore.group(0)
					print("\nSe ha detectado el archivo "+log4jCore.group(0)+", en la siguiente ruta:\n")
					print(">>\t"+rutaAbsoluta)
					coreJar = ZipFile(rutaAbsoluta, 'r')
					try:
						listado = coreJar.infolist()        
						for archivoClass in listado:        
							archivoJndiLookup = archivoClass.filename                
							if archivoJndiLookup[len(archivoJndiLookup)-16:len(archivoJndiLookup)] == 'JndiLookup.class':
								primerIndicador= False                
								print("\nSe ha detectado la vulnerabilidad CVE-2021-44228 en su sistema:")
								print("\nComprobación...\n")
								print(">>\t"+archivoJndiLookup[len(archivoJndiLookup)-16:len(archivoJndiLookup)])
								print("\n")
								print("¡¡¡Debe mitigar la vulnerabilidad CVE-2021-44228 cuanto antes!!!\n")
					finally:
						coreJar.close()
					break
	if primerIndicador:
	
		print("\nNo se detecto el archivo JndiLookup.class\n")
				
	if segundoIndicador:
	
		print("No se detecto el archivo: log4j-core*.jar  en la ruta: "+ruta+"\n")

#===========================INTERFAZ=============================

if len(sys.argv) <= 3 and len(sys.argv) >=2:
	
	if sys.argv[1] == '-d' or sys.argv[1] == '--directorio':
	
		escaner(sys.argv[2])

	elif sys.argv[1] == '-h' or sys.argv[1] == '--ayuda':

		imprimirAyuda()
		
	else:
		imprimirAyuda()
		
else:
 		imprimirAyuda()
 		
print("\nHecho por VenCERT-2022\n")
