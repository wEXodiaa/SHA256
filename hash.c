#include <stdio.h>

#include <string.h>

#include <stdint.h>

//=============== Affichage de notre résultat en octets pour debugage et comparaison avec le site =============================

uint32_t OctetsGroupMaker(unsigned char tab[], int pos) {
    return ((uint32_t) tab[pos] << 24) |
        ((uint32_t) tab[pos + 1] << 16) |
        ((uint32_t) tab[pos + 2] << 8) |
        ((uint32_t) tab[pos + 3]);
}

uint32_t ROTR(uint32_t nombreDeBase, int decalage) {
    return (nombreDeBase >> decalage) | (nombreDeBase << (32 - decalage));
}

uint32_t sigma0(uint32_t nombreDeBase) {
    return ROTR(nombreDeBase, 7) ^ ROTR(nombreDeBase, 18) ^ (nombreDeBase >> 3);
}

uint32_t sigma1(uint32_t nombreDeBase) {
    return ROTR(nombreDeBase, 17) ^ ROTR(nombreDeBase, 19) ^ (nombreDeBase >> 10);
}

int main() {

    char mdp[] = "motdepasseàhasher";
    int count = 0;
    unsigned char tab[65];

    //=============== Copiage du mot de passe et remplissage du bloc =============================

    while (count < 65) {
        if (mdp[count] == '\0' || count > strlen(mdp)) {
            tab[count] = 0;
            count++;
        } else {
            tab[count] = mdp[count];
            count++;
        }
    }
    tab[strlen(mdp)] = 0x80;

    // ================ Remplissage des 8 derniers octets ===============================

    unsigned long long tailleDuMessageEnBits = strlen(mdp) * 8;

    tab[56] = (tailleDuMessageEnBits >> 56) & 0xFF;
    tab[57] = (tailleDuMessageEnBits >> 48) & 0xFF;
    tab[58] = (tailleDuMessageEnBits >> 40) & 0xFF;
    tab[59] = (tailleDuMessageEnBits >> 32) & 0xFF;
    tab[60] = (tailleDuMessageEnBits >> 24) & 0xFF;
    tab[61] = (tailleDuMessageEnBits >> 16) & 0xFF;
    tab[62] = (tailleDuMessageEnBits >> 8) & 0xFF;
    tab[63] = tailleDuMessageEnBits & 0xFF;

    // ===================== Découpage en blocs de 32 bits ==============================
    uint32_t mots32bits[64];
    for (int compteur = 0; compteur < 16; compteur++) {
        mots32bits[compteur] = OctetsGroupMaker(tab, compteur * 4);
    }

    // ==================== Extension du bloc de 16 à 64 groupes ============================
    for (int blocNumber = 16; blocNumber < 64; blocNumber++) {
        mots32bits[blocNumber] = sigma1(mots32bits[blocNumber - 2]) + mots32bits[blocNumber - 7] +
            sigma0(mots32bits[blocNumber - 15]) + mots32bits[blocNumber - 16];
    }

    // ======= Initialisation des registres H0 à H7 (valeurs initiales SHA-256) ===========
    uint32_t H0 = 0x6a09e667;
    uint32_t H1 = 0xbb67ae85;
    uint32_t H2 = 0x3c6ef372;
    uint32_t H3 = 0xa54ff53a;
    uint32_t H4 = 0x510e527f;
    uint32_t H5 = 0x9b05688c;
    uint32_t H6 = 0x1f83d9ab;
    uint32_t H7 = 0x5be0cd19;

    // ======= Copie temporaire dans a, b, c, d, e, f, g, h avant traitement ============
    uint32_t a = H0;
    uint32_t b = H1;
    uint32_t c = H2;
    uint32_t d = H3;
    uint32_t e = H4;
    uint32_t f = H5;
    uint32_t g = H6;
    uint32_t h = H7;

    // ======= Constantes K de SHA-256 ===========
    const uint32_t constantList[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,
        0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74, 0x80deb1fe,
        0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc, 0x2de92c6f,
        0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,
        0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
        0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,
        0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,
        0xc67178f2
    };

    // ======= Boucle principale SHA-256 en 64 tours ==============================
    for (int i = 0; i < 64; i++) {
        uint32_t melangeE = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);

        uint32_t fonctionChoix = (e & f) ^ ((~e) & g);

        uint32_t temporaire1 = h + melangeE + fonctionChoix + constantList[i] + mots32bits[i];

        uint32_t melangeA = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);

        uint32_t fonctionMajorite = (a & b) ^ (a & c) ^ (b & c);

        uint32_t temporaire2 = melangeA + fonctionMajorite;

        h = g;
        g = f;
        f = e;
        e = d + temporaire1;
        d = c;
        c = b;
        b = a;
        a = temporaire1 + temporaire2;
    }

    // ======= Mise à jour finale des registres H0 à H7 ========================
    H0 += a;
    H1 += b;
    H2 += c;
    H3 += d;
    H4 += e;
    H5 += f;
    H6 += g;
    H7 += h;

    // ======= Affichage du hash final ==========================================
    printf("\nResultat final :\n");
    printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", H0, H1, H2, H3, H4, H5, H6, H7);

}
