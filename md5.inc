// md5.inc — Pure Pawn MD5 (RFC 1321) — Public Domain style
// Usage:
//   new hex[33];
//   MD5_Hex("hello", hex, sizeof hex); // -> 5d41402abc4b2a76b9719d911017c592

// --- 32-bit wrap helper ---
#if !defined U32
    #define U32(%0) ((%0) & 0xFFFFFFFF)
#endif

// --- unsigned right shift emulation (kein '>>>' nötig) ---
stock URShift(x, n)
{
    if (n <= 0) return x;
    if (n >= 32) return 0;
    // normaler >> ist in Pawn arithmetisch (füllt mit Vorzeichenbits),
    // wir maskieren das Ergebnis daher auf n Bits "unsigned".
    return (x >> n) & (0x7FFFFFFF >> (n - 1));
}

// --- rotate left, nutzt URShift statt >>> ---
#if !defined ROTL
    #define ROTL(%0,%1) U32( ( ( (%0) << (%1) ) | URShift(%0, (32 - (%1))) ) )
#endif

// MD5 boolean functions (RFC 1321)
#if !defined F
    #define F(%0,%1,%2) U32( ((%0) & (%1)) | (~(%0) & (%2)) )
#endif
#if !defined G
    #define G(%0,%1,%2) U32( ((%0) & (%2)) | ((%1) & ~(%2)) )
#endif
#if !defined H
    #define H(%0,%1,%2) U32( (%0) ^ (%1) ^ (%2) )
#endif
#if !defined I
    #define I(%0,%1,%2) U32( (%1) ^ ((%0) | ~(%2)) )
#endif

// K-Tabelle (sines of integers) & S (shifts)
static const MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const MD5_S[64] = {
    7,12,17,22,  7,12,17,22,  7,12,17,22,  7,12,17,22,
    5,9,14,20,   5,9,14,20,   5,9,14,20,   5,9,14,20,
    4,11,16,23,  4,11,16,23,  4,11,16,23,  4,11,16,23,
    6,10,15,21,  6,10,15,21,  6,10,15,21,  6,10,15,21
};

enum e_md5_ctx { A, B, C, D, LO, HI, NC, BUF[64] }

stock MD5_Init(ctx[e_md5_ctx])
{
    ctx[A]=0x67452301; ctx[B]=0xEFCDAB89; ctx[C]=0x98BADCFE; ctx[D]=0x10325476;
    ctx[LO]=0; ctx[HI]=0; ctx[NC]=0;
}

static stock md5_u32le(const bytes[], idx)
{
    // little-endian 32-bit load
    return U32(bytes[idx] | (bytes[idx+1] << 8) | (bytes[idx+2] << 16) | (bytes[idx+3] << 24));
}
static stock md5_store_u32le(dest[], idx, value)
{
    dest[idx]   = (value      ) & 0xFF;
    dest[idx+1] = (value >> 8 ) & 0xFF;
    dest[idx+2] = (value >> 16) & 0xFF;
    dest[idx+3] = (value >> 24) & 0xFF;
}

stock MD5_Update(ctx[e_md5_ctx], const data[], len)
{
    // bit length add (64-bit: HI:LO)
    new lo = ctx[LO], hi = ctx[HI];
    lo = U32(lo + len);
    if (lo < len) hi = U32(hi + 1);
    ctx[LO]=lo; ctx[HI]=hi;

    new n = ctx[NC];
    new i = 0;

    if (n && (n + len >= 64))
    {
        for (; n < 64; n++, i++) ctx[BUF][n] = data[i];
        MD5_Transform(ctx, ctx[BUF]);
        ctx[NC]=0;
    }
    for (; i + 63 < len; i += 64)
        MD5_Transform(ctx, data[i]);

    for (n = 0; i < len; i++, n++) ctx[BUF][n] = data[i];
    ctx[NC]=n;
}

stock MD5_Final(ctx[e_md5_ctx], out[16])
{
    new n = ctx[NC];

    // append 0x80
    ctx[BUF][n++] = 0x80;

    // pad with zeros to 56
    if (n > 56) {
        while (n < 64) ctx[BUF][n++] = 0;
        MD5_Transform(ctx, ctx[BUF]);
        n = 0;
    }
    while (n < 56) ctx[BUF][n++] = 0;

    // length in bits, little-endian (we tracked bytes in LO/HI)
    new lo = U32(ctx[LO] << 3);
    new hi = U32((ctx[HI] << 3) | (ctx[LO] >>> 29));
    md5_store_u32le(ctx[BUF], 56, lo);
    md5_store_u32le(ctx[BUF], 60, hi);

    MD5_Transform(ctx, ctx[BUF]);

    md5_store_u32le(out,  0, ctx[A]);
    md5_store_u32le(out,  4, ctx[B]);
    md5_store_u32le(out,  8, ctx[C]);
    md5_store_u32le(out, 12, ctx[D]);
}

stock MD5(const input[], out[16])
{
    new ctx[e_md5_ctx];
    MD5_Init(ctx);
    MD5_Update(ctx, input, strlen(input));
    MD5_Final(ctx, out);
}

stock MD5_Hex(const input[], out[], outsz)
{
    new bin[16];
    MD5(input, bin);
    md5_bin_to_hex(bin, 16, out, outsz);
}

stock md5_bin_to_hex(const bin[], binsz, out[], outsz)
{
    static const HEX[] = "0123456789abcdef";
    new j = 0;
    for (new i = 0; i < binsz && j + 1 < outsz; i++)
    {
        new b = bin[i] & 0xFF;
        if (j + 2 >= outsz) break;
        out[j++] = HEX[(b >>> 4) & 0xF];
        out[j++] = HEX[b & 0xF];
    }
    if (j < outsz) out[j] = '\0';
}

// ---- Core transform ----
stock MD5_Transform(ctx[e_md5_ctx], const block[])
{
    new a=ctx[A], b=ctx[B], c=ctx[C], d=ctx[D];
    new M[16];

    // 64 bytes -> 16 little-endian words
    for (new t = 0, i = 0; t < 16; t++, i += 4)
        M[t] = md5_u32le(block, i);

    for (new i = 0; i < 64; i++)
    {
        new f, g;
        if (i < 16)       { f = F(b,c,d); g = i; }
        else if (i < 32)  { f = G(b,c,d); g = (5*i + 1) & 15; }
        else if (i < 48)  { f = H(b,c,d); g = (3*i + 5) & 15; }
        else              { f = I(b,c,d); g = (7*i)     & 15; }

        new tmp = d;
        d = c;
        c = b;
        b = U32(b + ROTL(U32(a + f + MD5_K[i] + M[g]), MD5_S[i]));
        a = tmp;
    }

    ctx[A] = U32(ctx[A] + a);
    ctx[B] = U32(ctx[B] + b);
    ctx[C] = U32(ctx[C] + c);
    ctx[D] = U32(ctx[D] + d);
}
