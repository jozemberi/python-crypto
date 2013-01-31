# Labosi 1: Digitalni potpis
# Kolegij: Operacijski sustavi 2
# Fakultet organizacije i informatike Varaždin
# Autor: Josip Žemberi
# Tehnologija: python 3.3.0. + pycrypto 2.6., windows7
# Varaždin, 25.10.2012.

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import binascii # modul za ASCII reprezentaciju binarnih podataka

naz_dat_podaci = 'dat1.txt' #naziv datoteke s podacima
naz_dat_tajni_kljuc = 'tajni_kljuc.txt' #naziv datoteke koja sadrži AES ključ
naz_dat_privatni_kljuc = 'privatni_kljuc.txt' #naziv datoteke koja sadrži privatni RSA ključ
naz_dat_javni_kljuc = 'javni_kljuc.txt' #naziv datoteke koja sadrži javni RSA ključ

def pad_data(data):
    if len(data) % 16 == 0: # ako nije potreban padding
        return data
    else: # ako je potreban, računa se broj potrebnih bajtova
        potreban_padding = 15 - (len(data) % 16)
        data += '\x80' # uobičajen prvi bajt paddinga
        data += '\x00' * potreban_padding # ostali bajtovi 
        return data

def unpad_data(data):
    if not data: # ako je prosljeđen prazan string
        return data
    # ako je potrebno, uklanja '\x00' i '\x80' te vraća podatke
    try:
        data = data.rstrip('\x00')
        if data[-1] == '\x80':
            return data[:-1]
        else: # ako padding nije ni bilo vraća originalne podatke
            return data
    except (IOError, ValueError, RuntimeError, TypeError, NameError):
        return data

def generiranje_kljuca():
    generirani_tajni_kljuc = Random.new().read(32) # veličina ključa: 32*8 = 256 bita
    return generirani_tajni_kljuc
    
def generiranje_iv():
    rnd_iv = Random.new().read(AES.block_size)
    return rnd_iv

def aes_enkripcija(data, iv, kljuc):
    data = pad_data(data)
    aes = AES.new(kljuc, AES.MODE_CFB, iv)
    return aes.encrypt(data)
        
def aes_dekripcija(data, iv, kljuc):
    aes = AES.new(kljuc, AES.MODE_CFB, iv)
    data = aes.decrypt(data)
    return unpad_data(data.decode('utf-8', 'replace'))

def spremi(naziv_datoteke, data, mod='w+b'):
    f = open(naziv_datoteke, mod)
    f.write(data)
    f.close()

def ucitaj(naziv_datoteke, mod='r+b'):
    f = open(naziv_datoteke, mod)
    data = f.read()
    f.close()
    return data

def izbornik():
    print('*******************')
    print('>>> Glavni Izbornik')
    print('>> Trenutno odabrana datoteka:', naz_dat_podaci)
    print('Dostupne opcije: ')
    print('\ta) Odabir datoteke')
    print('\tb) Generiranje i pohranjivanje tajnog ključa (AES)')
    print('\tc) AES kriptiranje/dekriptiranje')
    print('\td) Stvaranje i pohranjivanje javnog i privatnog ključa (RSA)')
    print('\te) RSA kriptiranje/dekriptiranje')
    print('\tf) Izračun sažetka')
    print('\tg) Digitalno potpisivanje')
    print('\th) Provjera digitalnog potpisa')
    print('\tz) izlaz')
    return input('Vaš odabir: ')
    
odabir = ''

while odabir != 'z':
    odabir = izbornik()
    if odabir == 'a':
        print('=========================')
        print('>> Odabir Datoteke s Podacima')
        naz_dat_podaci = input('Naziv datoteke: ')
        
    elif odabir == 'b':
        print('=========================')
        print('>> Generiranje i Pohranjivanje Tajnog Ključa')
        print('Generiram tajni ključ ..')
        tajni_kljuc = generiranje_kljuca()
        print('Tajni ključ je generiran!')
        print('Veličina tajnog ključa:', len(tajni_kljuc) * 8, 'bita')
        tajni_kljuc = binascii.hexlify(tajni_kljuc)
        print('Tajni ključ:', str(tajni_kljuc, 'utf-8'))
        spremi(naz_dat_tajni_kljuc, tajni_kljuc)
        print('Tajni ključ je spremljen u datoteku', naz_dat_tajni_kljuc + '.')
       
    elif odabir == 'c':
        print('=========================')
        print('>> AES Kriptiranje/Dekriptiranje')
        print('Odabrana datoteka:', naz_dat_podaci)
        print('Odaberite: ')
        print('\ta) za KRIPTIRANJE')
        print('\tb) za DEKRIPTIRANJE')
        print('\tc) za ODABIR druge DATOTEKE')
        print('\tz) za povratak na GLAVNI IZBORNIK')
        pod_odabir = input('Vaš odabir: ')
        if pod_odabir == 'a':
            print('=========================')
            print('> AES Kriptiranje')
            try:
                ucitani_podaci = ucitaj(naz_dat_podaci)
                ucitani_podaci = ucitani_podaci.decode('utf-8', 'replace')
                print('Učitani podaci:', ucitani_podaci)
                #print('Generiram IV..')
                iv = generiranje_iv()
                #print('IV generiran!')
                #print('IV:', str(binascii.hexlify(iv), 'utf-8'))
                print('Učitavam tajni ključ iz datoteke', naz_dat_tajni_kljuc + '..')
                tajni_kljuc = ucitaj(naz_dat_tajni_kljuc)
                print('Tajni ključ je učitan!')
                print('Tajni ključ:', str(tajni_kljuc, 'utf-8'))
                tajni_kljuc = binascii.unhexlify(tajni_kljuc)
                print('Kriptiram podatke..')
                kriptirani_podaci = aes_enkripcija(ucitani_podaci, iv, tajni_kljuc)
                kriptirani_podaci_za_upis = iv + kriptirani_podaci
                kriptirani_podaci_za_upis = binascii.hexlify(kriptirani_podaci_za_upis)
                print('Kriptirani podaci:', str(kriptirani_podaci_za_upis[16:], 'utf-8'))
                spremi(naz_dat_podaci, kriptirani_podaci_za_upis)
                print('Kriptirani podaci su spremljeni u datoteku', naz_dat_podaci)
            except (IOError, ValueError, RuntimeError, TypeError, NameError):
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                print('Kriptiranje nije uspjelo!')
                print('Provjerite da li odabrana datoteka postoji.')
                print('Provjerite da li ste generirali AES ključ.')
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                
        elif pod_odabir == 'b':
            print('=========================')
            print('> AES Dekriptiranje')
            try:
                ucitani_podaci_hex = ucitaj(naz_dat_podaci)
                ucitani_podaci = ucitani_podaci_hex.decode('utf-8', 'replace')
                print('Učitani podaci:', ucitani_podaci)
                ucitani_podaci = binascii.unhexlify(ucitani_podaci_hex)
                print('Učitavam tajni ključ iz datoteke', naz_dat_tajni_kljuc,'..')
                tajni_kljuc = ucitaj(naz_dat_tajni_kljuc)
                print('Tajni ključ je učitan!')
                print('Tajni ključ:', str(tajni_kljuc, 'utf-8'))
                tajni_kljuc = binascii.unhexlify(tajni_kljuc)
                iv = ucitani_podaci[:16]
                kriptirani_podaci = ucitani_podaci[16:]
                dekriptirani_podaci = aes_dekripcija(kriptirani_podaci, iv, tajni_kljuc)
                print('Dekriptirani podaci:', dekriptirani_podaci)
                spremi(naz_dat_podaci, dekriptirani_podaci.encode())
                print('Dekriptirani podaci su spremljeni u datoteku', naz_dat_podaci)
            except (IOError, ValueError, RuntimeError, TypeError, NameError):
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                print('Dekriptiranje nije uspjelo!')
                print('Provjerite da li ste odabrali dobru datoteku.')
                print('Provjerite valjanost datoteke koja sadrži tajni ključ.')
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                
        elif pod_odabir == 'c':
            print('=========================')
            print('> Odabir Datoteke s Podacima')
            naz_dat_podaci = input('Naziv datoteke: ')
            
    elif odabir == 'd':
        print('=========================')
        print('>> Generiranje RSA KLjuča')
        print('Generiram RSA ključ..')
        kljuc = RSA.generate(2048)
        print('Veličina generiranog ključa:', kljuc.size() + 1, 'bita')
        print('Privatni ključ:', str(kljuc.exportKey(), 'utf-8'))
        print('Javni ključ:', str(kljuc.publickey().exportKey(), 'utf-8'))     
        spremi(naz_dat_privatni_kljuc,kljuc.exportKey())
        print('Privatni ključ je spremljen u datoteku', naz_dat_privatni_kljuc)   
        spremi(naz_dat_javni_kljuc, kljuc.publickey().exportKey())
        print('Javni ključ je spremljen u datoteku', naz_dat_javni_kljuc)
        
    elif odabir == 'e':
        print('=========================')
        print('>> RSA Kriptiranje/Dekriptiranje')
        print('Odabrana datoteka:', naz_dat_podaci)
        print('Odaberite: ')
        print('\ta) za KRIPTIRANJE')
        print('\tb) za DEKRIPTIRANJE')
        print('\tc) za ODABIR druge DATOTEKE')
        print('\tz) za povratak na GLAVNI IZBORNIK')
        pod_odabir = input('Vaš odabir: ')
        if pod_odabir == 'a':
            print('=========================')
            print('> RSA Kriptiranje')
            try:  
                ucitani_podaci = ucitaj(naz_dat_podaci)
                print('Učitani podaci:', ucitani_podaci.decode('utf-8', 'replace'))
                print('Učitavam javni ključ iz datoteke', naz_dat_javni_kljuc + '..')
                javni_kljuc = RSA.importKey(ucitaj(naz_dat_javni_kljuc))
                print('Javni ključ je učitan!')
                print('Javni ključ:', str(javni_kljuc.publickey().exportKey(), 'utf-8'))
                print('Kriptiram podatke..')
                kriptirani_podaci  = javni_kljuc.encrypt(ucitani_podaci, None)
                kriptirani_podaci = kriptirani_podaci[0]
                kriptirani_podaci = binascii.hexlify(kriptirani_podaci) 
                print ('Kriptirani podaci:', str(kriptirani_podaci, 'utf-8'))
                spremi(naz_dat_podaci, kriptirani_podaci)
                print('Kriptirani podaci su spremljeni u datoteku', naz_dat_podaci)
            except (IOError, ValueError, RuntimeError, TypeError, NameError):
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                print('Kriptiranje nije uspjelo!')
                print('Provjerite da li ste odabrali željenu datoteku')
                print('Provjerite da li ste kreirali RSA ključ')
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                
        elif pod_odabir == 'b':
            print('=========================')
            print('> RSA Dekriptiranje')
            try:
                ucitani_podaci_hex = ucitaj(naz_dat_podaci)
                ucitani_podaci = ucitani_podaci_hex.decode('utf-8', 'replace')
                ucitani_podaci = binascii.unhexlify(ucitani_podaci)
                print('Učitani podaci:', str(ucitani_podaci_hex, 'utf-8'))
                print('Učitavam privatni ključ iz datoteke', naz_dat_privatni_kljuc + '..')
                privatni_kljuc = RSA.importKey(ucitaj(naz_dat_privatni_kljuc))
                print('Privatni ključ je učitan!')
                print('Privatni ključ:', str(privatni_kljuc.exportKey(), 'utf-8'))
                dekriptirani_podaci = privatni_kljuc.decrypt(ucitani_podaci)
                print('Dekriptirani podaci:', dekriptirani_podaci.decode('utf-8', 'replace'))
                spremi(naz_dat_podaci, dekriptirani_podaci)
                print('Dekriptirani podaci su spremljeni u datoteku', naz_dat_podaci)
            except (IOError, ValueError, RuntimeError, TypeError, NameError):
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                print('Dekriptiranje nije uspjelo!')
                print('Provjerite da li ste odabrali valjanu datoteku')
                print('Provjerite valjanost datoteke koja sadrži javni ključ')
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                
        elif pod_odabir == 'c':
            print('=========================')
            print('> Odabir Datoteke s Podacima')
            naz_dat_podaci = input('Naziv datoteke: ')
            
    elif odabir == 'f':
        print('=========================')
        print('>> Izračun sažetka')
        print('Odabrana datoteka:', naz_dat_podaci)
        ucitani_podaci = ucitaj(naz_dat_podaci)
        print('Učitani podaci:', ucitani_podaci.decode('utf-8', 'replace'))
        print('Računam sažetak..')
        sazetak = SHA.new()
        sazetak.update(ucitani_podaci)
        print('Sažetak:', sazetak.hexdigest())
        #print('Veličina sažetka:', sazetak.digest_size * 8, 'bita')
    elif odabir == 'g':
        print('=========================')
        print('>> Digitalni potpis')
        print('Odabrana datoteka:', naz_dat_podaci)
        try:
            ucitani_podaci = ucitaj(naz_dat_podaci)
            print('Učitani podaci:', ucitani_podaci.decode('utf-8', 'replace'))
            print('Učitavam privatni ključ iz datoteke', naz_dat_privatni_kljuc,'..')
            privatni_kljuc = RSA.importKey(ucitaj(naz_dat_privatni_kljuc))
            print('Privatni ključ je učitan!')
            print('Privatni ključ:', str(privatni_kljuc.exportKey(), 'utf-8'))
            sazetak = SHA.new()
            sazetak.update(ucitani_podaci)
            print('Sažetak:', sazetak.hexdigest())
            #print('Veličina sažetka:', sazetak.digest_size * 8, 'bita')
            digitalni_potpis = privatni_kljuc.sign(sazetak.digest(), None)[0]
            digitalni_potpis = str(digitalni_potpis)
            print('Digitalni_potpis:', digitalni_potpis)
            podaci_za_upis = 'Digitalni_potpis:' + digitalni_potpis.strip()
            naz_dat_potpisano = 'potpisano_' + naz_dat_podaci
            spremi(naz_dat_potpisano, ucitani_podaci)
            spremi(naz_dat_potpisano, podaci_za_upis, 'a')
            print('Sadržaj datoteke', naz_dat_podaci, 'je digitalno potpisan i spremljen u', naz_dat_potpisano)
        except (IOError, ValueError, RuntimeError, TypeError, NameError):
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                print('Digitalno potpisivanje nije uspjelo!')
                print('Provjerite da li ste odabrali valjanu datoteku')
                print('Provjerite valjanost datoteke koja sadrži privatni ključ')
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    elif odabir == 'h':
        print('=========================')
        print('>> Provjera digitalnog potpisa')
        print('Odabrana datoteka:', naz_dat_podaci)
        try:
            ucitani_podaci = ucitaj(naz_dat_podaci)
            ucitani_podaci = ucitani_podaci.decode('utf-8', 'replace')
            print('Učitani podaci', ucitani_podaci)
            print('Učitavam javni ključ iz datoteke', naz_dat_javni_kljuc,'..')
            javni_kljuc = RSA.importKey(ucitaj(naz_dat_javni_kljuc))
            print('Javni ključ je učitan!')
            print('Javni ključ:', str(javni_kljuc.publickey().exportKey(), 'utf-8'))
            if 'Digitalni_potpis:' in ucitani_podaci:
                potpis = ucitani_podaci.partition('Digitalni_potpis:')[2]
                ucitani_podaci = ucitani_podaci.partition('Digitalni_potpis:')[0]
            h = SHA.new()
            h.update(ucitani_podaci.encode('utf-8'))
            ok = javni_kljuc.verify(h.digest(),(int(potpis),))
            if ok:
                print ("Digitalni potpis JE AUTENTIČAN.")
            else:
                print ("Digitalni potpis NIJE AUTENTIČAN.")
        except (IOError, ValueError, RuntimeError, TypeError, NameError):        
            print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            print('Provjera digitalnog potpisa nije uspjela!')
            print('Provjerite da li ste odabrali valjanu datoteku')
            print('Provjerite valjanost datoteke koja sadrži javni ključ')
            print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')

