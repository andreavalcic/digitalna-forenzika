# digitalna-forenzika
**Naslov teme:**
Steganografija u QR kodovima

**Opis teme:**
Tema se bavi istraživanjem tehnike steganografije korišćenjem QR kodova, analizirajući njihovu pogodnost za skrivanje informacija kroz manipulaciju nivoa ispravljanja grešaka. Teorijski deo obuhvata pregled koncepta steganografije, primene QR kodova i postojećih alata za ovu svrhu. Praktična implementacija uključuje razvoj alata u Pythonu za kodiranje tajnih poruka u QR kodove, koristeći biblioteke kao što su qrcode za generisanje QR kodova i Pillow za obradu slike.


## Postavka projekta

### Preduslovi za pokretanje

**Operativni sistem po izboru (macOS):**  
- **Python 3:** verzija 3.12.3  
- **Visual Studio Code**: (ili drugi editor po izboru)
- **Aktivno Python virtuelno okruženje**

**Instalacija i podešavanje projekta**
1. **Kreirati direktorijum projekta:**
      * digitalna-forenzika
2. **Kreirati Python virtuelno okruženje:***
      * python3 -m venv venv
3. **Aktivirati virtuelno okruženje:**
      * source venv/bin/activate
4. **Instalirati neophodne Python biblioteke**
      * qrcode
      * pillow
      * numpy

**Pokretanje aplikacije**
1. cd digitalna-forenzika
2. source venv/bin/activate
3. python qr_stego.py
