unit uC512Cipher;

{
  uC512Cipher — ALB_C512 (C512) Sponge-based Authenticated Encryption.

  A sponge-based symmetric cipher using:
    - 1024-bit internal state (512-bit rate + 512-bit capacity)
    - 512-bit key, 256-bit nonce, 256-bit authentication tag
    - Sponge construction (MonkeyDuplex) for single-pass AEAD
    - Keccak-chi S-box + NTT lattice mixing round function
    - Dual-phase rounds: p^a (24) for init/finalize, p^b (12) for data

  Wire format: Nonce(32) || Ciphertext || Tag(32)
}

interface

uses
  System.SysUtils, System.Classes, System.Math, Winapi.Windows;

const
  C512_KEY_SIZE = 64;
  C512_NONCE_SIZE = 32;
  C512_TAG_SIZE = 32;
  C512_STATE_SIZE = 128;
  C512_RATE_SIZE = 64;
  C512_ROUNDS_A = 24;
  C512_ROUNDS_B = 12;
  C512_KDF_ROUNDS = 4;

// ── C512-AEAD public API ───────────────────────────────────────────────────

function C512_Encrypt(
  const Key: TBytes;      // 64 bytes (512 bits)
  const Nonce: TBytes;    // 32 bytes (256 bits)
  const AAD: TBytes;      // arbitrary associated data (can be nil)
  const Plaintext: TBytes // arbitrary plaintext (can be nil)
): TBytes;                // Returns: Ciphertext || Tag(32)

function C512_Decrypt(
  const Key: TBytes;      // 64 bytes (512 bits)
  const Nonce: TBytes;    // 32 bytes (256 bits)
  const AAD: TBytes;      // same AAD used during encryption
  const Data: TBytes      // Ciphertext || Tag(32)
): TBytes;                // Returns plaintext or raises on auth failure

// ── Convenience wrappers (auto-generate nonce) ─────────────────────────────

function C512_EncryptWithNonce(
  const Key: TBytes;
  const AAD: TBytes;
  const Plaintext: TBytes
): TBytes;                // Returns: Nonce(32) || Ciphertext || Tag(32)

function C512_DecryptWithNonce(
  const Key: TBytes;
  const AAD: TBytes;
  const Data: TBytes      // Nonce(32) || Ciphertext || Tag(32)
): TBytes;

// ── Low-level (exposed for testing) ────────────────────────────────────────

type
  TC512State = array[0..31] of UInt32;  // 32 lanes × 32 bits = 1024 bits

procedure C512_Permutation(var State: TC512State; Rounds: Integer;
  const RoundKeys: array of TC512State);
procedure C512_BootstrapPermutation(var State: TC512State; Rounds: Integer);
procedure C512_KeySchedule(const MasterKey: TBytes;
  out RoundKeys: array of TC512State);
procedure C512_InitState(var State: TC512State; const Key, Nonce: TBytes);

function C512_BytesEqual(const A, B: TBytes): Boolean;

implementation

const
  PROV_RSA_FULL = 1;
  CRYPT_VERIFYCONTEXT = $F0000000;

function CryptAcquireContext(var phProv: NativeUInt; pszContainer: PChar;
  pszProvider: PChar; dwProvType, dwFlags: DWORD): BOOL; stdcall;
  external 'advapi32.dll' name 'CryptAcquireContextW';
function CryptGenRandom(hProv: NativeUInt; dwLen: DWORD; pbBuffer: PByte): BOOL; stdcall;
  external 'advapi32.dll' name 'CryptGenRandom';
function CryptReleaseContext(hProv: NativeUInt; dwFlags: DWORD): BOOL; stdcall;
  external 'advapi32.dll' name 'CryptReleaseContext';

// ── Local helpers ──────────────────────────────────────────────────────────

function ConcatBytes(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

function SliceBytes(const Data: TBytes; Offset, Count: Integer): TBytes;
begin
  if Count < 0 then
    Count := 0;
  if Offset < 0 then
    Offset := 0;
  if Offset > Length(Data) then
    Offset := Length(Data);
  if Offset + Count > Length(Data) then
    Count := Length(Data) - Offset;

  SetLength(Result, Count);
  if Count > 0 then
    Move(Data[Offset], Result[0], Count);
end;

function C512_BytesEqual(const A, B: TBytes): Boolean;
var
  I: Integer;
  Diff: Byte;
begin
  if Length(A) <> Length(B) then
    Exit(False);

  Diff := 0;
  for I := 0 to Length(A) - 1 do
    Diff := Diff or (A[I] xor B[I]);
  Result := Diff = 0;
end;

function RandomBytes(Size: Integer): TBytes;
var
  Provider: NativeUInt;
begin
  if Size < 0 then
    raise Exception.Create('C512: random byte count must be non-negative');

  SetLength(Result, Size);
  if Size = 0 then
    Exit;

  Provider := 0;
  if not CryptAcquireContext(Provider, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
    RaiseLastOSError;
  try
    if not CryptGenRandom(Provider, DWORD(Size), @Result[0]) then
      RaiseLastOSError;
  finally
    CryptReleaseContext(Provider, 0);
  end;
end;

// ── Round Constants (derived from fractional bits of sqrt(2) and sqrt(3)) ──

const
  ROUND_CONSTANTS: array[0..23] of UInt64 = (
    $6A09E667F3BCC908, $BB67AE8584CAA73B,
    $3C6EF372FE94F82B, $A54FF53A5F1D36F1,
    $510E527FADE682D1, $9B05688C2B3E6C1F,
    $1F83D9ABFB41BD6B, $5BE0CD19137E2179,
    $428A2F98D728AE22, $7137449123EF65CD,
    $B5C0FBCFEC4D3B2F, $E9B5DBA58189DBBC,
    $3956C25BF348B538, $59F111F1B605D019,
    $923F82A4AF194F9B, $AB1C5ED5DA6D8118,
    $D807AA98A3030242, $12835B0145706FBE,
    $243185BE4EE4B28C, $550C7DC3D5FFB4E2,
    $72BE5D74F27B896F, $80DEB1FE3B1696B1,
    $9BDC06A725C71235, $C19BF174CF692694
  );

  OMEGA: array[0..15] of UInt32 = (
    $00000001, $6A09E667, $BB67AE85, $3C6EF372,
    $A54FF53A, $510E527F, $9B05688C, $1F83D9AB,
    $5BE0CD19, $428A2F98, $71374491, $B5C0FBCF,
    $E9B5DBA5, $3956C25B, $59F111F1, $923F82A4
  );

// ── Helper: State <-> Bytes conversion ─────────────────────────────────────

procedure StateFromBytes(out State: TC512State; const B: TBytes);
var
  I: Integer;
begin
  if Length(B) < C512_STATE_SIZE then
    raise Exception.Create('C512: state buffer must be at least 128 bytes');
  for I := 0 to 31 do
    State[I] := PUInt32(@B[I * 4])^;
end;

procedure StateToBytes(const State: TC512State; out B: TBytes);
var
  I: Integer;
begin
  SetLength(B, 128);
  for I := 0 to 31 do
    PUInt32(@B[I * 4])^ := State[I];
end;

// ── Layer 1: Round Constants (p_C) ─────────────────────────────────────────

procedure ApplyRoundConstant(var State: TC512State; RoundIndex: Integer);
var
  RC: UInt64;
begin
  RC := ROUND_CONSTANTS[RoundIndex mod 24];
  State[16] := State[16] xor UInt32(RC);
  State[17] := State[17] xor UInt32(RC shr 32);
end;

// ── Layer 1b: Theta diffusion ──────────────────────────────────────────────

const
  ROTATION_OFFSETS: array[0..31] of Integer = (
    0, 1, 3, 6, 10, 15, 21, 28,
    2, 5, 9, 14, 20, 27, 3, 12,
    4, 8, 13, 19, 26, 1, 7, 16,
    11, 18, 25, 31, 17, 24, 30, 22
  );

function RotL32(X: UInt32; N: Integer): UInt32; inline;
begin
  N := N and 31;
  if N = 0 then
    Exit(X);
  Result := (X shl N) or (X shr (32 - N));
end;

procedure ApplyTheta(var State: TC512State);
var
  Parity: array[0..31] of UInt32;
  I: Integer;
begin
  for I := 0 to 31 do
    Parity[I] := State[(I + 32 - 5) mod 32]
      xor RotL32(State[(I + 5) mod 32], 7)
      xor State[(I + 32 - 13) mod 32]
      xor RotL32(State[(I + 13) mod 32], 19);
  for I := 0 to 31 do
    State[I] := State[I] xor Parity[I];
  for I := 0 to 31 do
    State[I] := RotL32(State[I], ROTATION_OFFSETS[I]);
end;

// ── Layer 2: Non-linear S-box (p_S) — Keccak chi across 32 lanes ──────────

procedure ApplyChi(var State: TC512State);
var
  Temp: TC512State;
  I: Integer;
begin
  Move(State, Temp, SizeOf(TC512State));
  for I := 0 to 31 do
    State[I] := Temp[I] xor ((not Temp[(I + 1) mod 32]) and Temp[(I + 2) mod 32]);
end;

// ── Layer 3: Lattice NTT Mixing (p_L) ─────────────────────────────────────

procedure ApplyNTTButterfly(var State: TC512State);
var
  Step, Group, J, Idx1, Idx2: Integer;
  Temp: UInt32;
  OmegaIdx: Integer;
begin
  Step := 8;
  while Step >= 1 do
  begin
    Group := 0;
    while Group < 16 do
    begin
      for J := 0 to Step - 1 do
      begin
        Idx1 := Group + J;
        Idx2 := Group + J + Step;
        OmegaIdx := (J * (16 div (Step * 2))) mod 16;
        Temp := UInt32(UInt64(State[Idx2]) * UInt64(OMEGA[OmegaIdx]));
        State[Idx2] := State[Idx1] - Temp;
        State[Idx1] := State[Idx1] + Temp;
      end;
      Group := Group + Step * 2;
    end;
    Step := Step div 2;
  end;

  Step := 8;
  while Step >= 1 do
  begin
    Group := 0;
    while Group < 16 do
    begin
      for J := 0 to Step - 1 do
      begin
        Idx1 := 16 + Group + J;
        Idx2 := 16 + Group + J + Step;
        OmegaIdx := (J * (16 div (Step * 2))) mod 16;
        Temp := UInt32(UInt64(State[Idx2]) * UInt64(OMEGA[OmegaIdx]));
        State[Idx2] := State[Idx1] - Temp;
        State[Idx1] := State[Idx1] + Temp;
      end;
      Group := Group + Step * 2;
    end;
    Step := Step div 2;
  end;

  for J := 0 to 15 do
  begin
    Temp := State[J];
    State[J] := State[J] xor RotL32(State[16 + J], 11);
    State[16 + J] := State[16 + J] xor RotL32(Temp, 23);
  end;
end;

procedure ApplyRoundKeyInjection(var State: TC512State;
  const RoundKey: TC512State);
var
  I: Integer;
begin
  for I := 0 to 31 do
    State[I] := State[I] xor RoundKey[I];
end;

// ── Full Permutation ───────────────────────────────────────────────────────

procedure C512_Permutation(var State: TC512State; Rounds: Integer;
  const RoundKeys: array of TC512State);
var
  I: Integer;
begin
  if (Rounds < 0) or (Rounds > 24) then
    raise Exception.Create('Invalid round count');
  for I := 0 to Rounds - 1 do
  begin
    ApplyRoundConstant(State, I);
    ApplyTheta(State);
    ApplyChi(State);
    ApplyNTTButterfly(State);
    if Length(RoundKeys) = 0 then raise Exception.Create('Empty round keys');
    ApplyRoundKeyInjection(State, RoundKeys[I mod Length(RoundKeys)]);
  end;
end;

// ── Bootstrap Permutation (for key schedule — no round key injection) ──────

procedure C512_BootstrapPermutation(var State: TC512State; Rounds: Integer);
var
  I: Integer;
begin
  for I := 0 to Rounds - 1 do
  begin
    ApplyRoundConstant(State, I);
    ApplyTheta(State);
    ApplyChi(State);
    ApplyNTTButterfly(State);
  end;
end;

// ── Key Schedule ───────────────────────────────────────────────────────────

procedure C512_KeySchedule(const MasterKey: TBytes;
  out RoundKeys: array of TC512State);
var
  C: TC512State;
  RevKey: TBytes;
  Combined: TBytes;
  R, I: Integer;
begin
  if GetEnvironmentVariable('ALB_C512_EXPERIMENTAL') <> '1' then
    raise Exception.Create('C512 is research only; explicit experimental opt-in required');
  if Length(MasterKey) <> C512_KEY_SIZE then
    raise Exception.Create('C512: key must be 64 bytes');

  SetLength(RevKey, C512_KEY_SIZE);
  for I := 0 to C512_KEY_SIZE - 1 do
    RevKey[I] := MasterKey[C512_KEY_SIZE - 1 - I];
  Combined := ConcatBytes(MasterKey, RevKey);
  StateFromBytes(C, Combined);

  for R := 0 to High(RoundKeys) do
  begin
    C512_BootstrapPermutation(C, C512_KDF_ROUNDS);
    RoundKeys[R] := C;
    C[0] := C[0] xor UInt32(R);
    C[1] := C[1] xor $43353230;
  end;

  FillChar(RevKey[0], Length(RevKey), 0);
  FillChar(Combined[0], Length(Combined), 0);
end;

// ── State Initialization ───────────────────────────────────────────────────

procedure C512_InitState(var State: TC512State; const Key, Nonce: TBytes);
var
  InitBytes: TBytes;
  IV: UInt64;
begin
  if Length(Key) <> C512_KEY_SIZE then
    raise Exception.Create('C512: key must be 64 bytes');
  if Length(Nonce) <> C512_NONCE_SIZE then
    raise Exception.Create('C512: nonce must be 32 bytes');

  SetLength(InitBytes, C512_STATE_SIZE);
  FillChar(InitBytes[0], C512_STATE_SIZE, 0);

  IV := $80500C1800000002;
  PUInt64(@InitBytes[0])^ := IV;
  Move(Key[0], InitBytes[8], C512_KEY_SIZE);
  Move(Nonce[0], InitBytes[72], C512_NONCE_SIZE);

  StateFromBytes(State, InitBytes);
  FillChar(InitBytes[0], C512_STATE_SIZE, 0);
end;

// ── Sponge Padding ─────────────────────────────────────────────────────────

function C512_Pad(const Data: TBytes; BlockSize: Integer): TBytes;
var
  PadLen: Integer;
  DataLen: Integer;
begin
  DataLen := Length(Data);
  PadLen := BlockSize - (DataLen mod BlockSize);
  if PadLen = 0 then
    PadLen := BlockSize;
  SetLength(Result, DataLen + PadLen);
  if DataLen > 0 then
    Move(Data[0], Result[0], DataLen);
  Result[DataLen] := $80;
  if PadLen > 1 then
    FillChar(Result[DataLen + 1], PadLen - 1, 0);
end;

// ── XOR into state rate portion ────────────────────────────────────────────

procedure XORBlockIntoState(var State: TC512State; const Block: TBytes;
  Offset: Integer);
var
  I: Integer;
  V: UInt32;
begin
  for I := 0 to 15 do
  begin
    V := PUInt32(@Block[Offset + I * 4])^;
    State[I] := State[I] xor V;
  end;
end;

procedure ExtractRateBytes(const State: TC512State; out Block: TBytes;
  Len: Integer);
var
  I: Integer;
begin
  SetLength(Block, Len);
  for I := 0 to Min(15, (Len - 1) div 4) do
  begin
    if (I * 4 + 4) <= Len then
      PUInt32(@Block[I * 4])^ := State[I]
    else
    begin
      Move(State[I], Block[I * 4], Len - I * 4);
    end;
  end;
end;

// ── C512 Encrypt (AEAD) ───────────────────────────────────────────────────

function C512_Encrypt(const Key, Nonce, AAD, Plaintext: TBytes): TBytes;
var
  State: TC512State;
  RoundKeys: array[0..23] of TC512State;
  AADPadded: TBytes;
  Ciphertext, Tag: TBytes;
  Absorb: TBytes;
  FullBlocks, Remaining, I, J, Off: Integer;
begin
  if Length(Key) <> C512_KEY_SIZE then
    raise Exception.Create('C512: key must be 64 bytes');
  if Length(Nonce) <> C512_NONCE_SIZE then
    raise Exception.Create('C512: nonce must be 32 bytes');

  C512_KeySchedule(Key, RoundKeys);
  C512_InitState(State, Key, Nonce);
  C512_Permutation(State, C512_ROUNDS_A, RoundKeys);

  if Length(AAD) > 0 then
  begin
    AADPadded := C512_Pad(AAD, C512_RATE_SIZE);
    for I := 0 to (Length(AADPadded) div C512_RATE_SIZE) - 1 do
    begin
      XORBlockIntoState(State, AADPadded, I * C512_RATE_SIZE);
      C512_Permutation(State, C512_ROUNDS_B, RoundKeys);
    end;
  end;

  State[31] := State[31] xor $00000002;

  FullBlocks := Length(Plaintext) div C512_RATE_SIZE;
  Remaining := Length(Plaintext) mod C512_RATE_SIZE;
  SetLength(Ciphertext, Length(Plaintext));
  SetLength(Absorb, C512_RATE_SIZE);

  for I := 0 to FullBlocks - 1 do
  begin
    Off := I * C512_RATE_SIZE;
    for J := 0 to C512_RATE_SIZE - 1 do
      Ciphertext[Off + J] :=
        Byte(State[J div 4] shr ((J mod 4) * 8)) xor Plaintext[Off + J];
    Move(Plaintext[Off], Absorb[0], C512_RATE_SIZE);
    XORBlockIntoState(State, Absorb, 0);
    C512_Permutation(State, C512_ROUNDS_B, RoundKeys);
  end;

  FillChar(Absorb[0], C512_RATE_SIZE, 0);
  if Remaining > 0 then
  begin
    Off := FullBlocks * C512_RATE_SIZE;
    for J := 0 to Remaining - 1 do
    begin
      Ciphertext[Off + J] :=
        Byte(State[J div 4] shr ((J mod 4) * 8)) xor Plaintext[Off + J];
      Absorb[J] := Plaintext[Off + J];
    end;
  end;
  Absorb[Remaining] := $80;
  XORBlockIntoState(State, Absorb, 0);
  C512_Permutation(State, C512_ROUNDS_B, RoundKeys);

  C512_Permutation(State, C512_ROUNDS_A, RoundKeys);

  // Tag domain separation + squeeze
  State[31] := State[31] xor $54414732;
  C512_Permutation(State, C512_ROUNDS_A, RoundKeys);

  SetLength(Tag, C512_TAG_SIZE);
  for I := 0 to 7 do
    PUInt32(@Tag[I * 4])^ := State[I];

  Result := ConcatBytes(Ciphertext, Tag);
end;

// ── C512 Decrypt (AEAD) ───────────────────────────────────────────────────

function C512_Decrypt(const Key, Nonce, AAD, Data: TBytes): TBytes;
var
  State: TC512State;
  RoundKeys: array[0..23] of TC512State;
  AADPadded: TBytes;
  Ciphertext, Tag, ExpectedTag: TBytes;
  Absorb: TBytes;
  FullBlocks, Remaining, I, J, Off: Integer;
  PlainByte: Byte;
begin
  if Length(Key) <> C512_KEY_SIZE then
    raise Exception.Create('C512: key must be 64 bytes');
  if Length(Nonce) <> C512_NONCE_SIZE then
    raise Exception.Create('C512: nonce must be 32 bytes');
  if Length(Data) < C512_TAG_SIZE then
    raise Exception.Create('C512: data too short');

  Ciphertext := SliceBytes(Data, 0, Length(Data) - C512_TAG_SIZE);
  Tag := SliceBytes(Data, Length(Data) - C512_TAG_SIZE, C512_TAG_SIZE);

  C512_KeySchedule(Key, RoundKeys);
  C512_InitState(State, Key, Nonce);
  C512_Permutation(State, C512_ROUNDS_A, RoundKeys);

  if Length(AAD) > 0 then
  begin
    AADPadded := C512_Pad(AAD, C512_RATE_SIZE);
    for I := 0 to (Length(AADPadded) div C512_RATE_SIZE) - 1 do
    begin
      XORBlockIntoState(State, AADPadded, I * C512_RATE_SIZE);
      C512_Permutation(State, C512_ROUNDS_B, RoundKeys);
    end;
  end;

  State[31] := State[31] xor $00000002;

  FullBlocks := Length(Ciphertext) div C512_RATE_SIZE;
  Remaining := Length(Ciphertext) mod C512_RATE_SIZE;
  SetLength(Result, Length(Ciphertext));
  SetLength(Absorb, C512_RATE_SIZE);

  for I := 0 to FullBlocks - 1 do
  begin
    Off := I * C512_RATE_SIZE;
    FillChar(Absorb[0], C512_RATE_SIZE, 0);
    for J := 0 to C512_RATE_SIZE - 1 do
    begin
      PlainByte := Byte(State[J div 4] shr ((J mod 4) * 8)) xor
                   Ciphertext[Off + J];
      Result[Off + J] := PlainByte;
      Absorb[J] := PlainByte;
    end;
    XORBlockIntoState(State, Absorb, 0);
    C512_Permutation(State, C512_ROUNDS_B, RoundKeys);
  end;

  FillChar(Absorb[0], C512_RATE_SIZE, 0);
  if Remaining > 0 then
  begin
    Off := FullBlocks * C512_RATE_SIZE;
    for J := 0 to Remaining - 1 do
    begin
      PlainByte := Byte(State[J div 4] shr ((J mod 4) * 8)) xor
                   Ciphertext[Off + J];
      Result[Off + J] := PlainByte;
      Absorb[J] := PlainByte;
    end;
  end;
  Absorb[Remaining] := $80;
  XORBlockIntoState(State, Absorb, 0);
  C512_Permutation(State, C512_ROUNDS_B, RoundKeys);

  C512_Permutation(State, C512_ROUNDS_A, RoundKeys);

  // Tag domain separation + squeeze
  State[31] := State[31] xor $54414732;
  C512_Permutation(State, C512_ROUNDS_A, RoundKeys);

  SetLength(ExpectedTag, C512_TAG_SIZE);
  for I := 0 to 7 do
    PUInt32(@ExpectedTag[I * 4])^ := State[I];

  if not C512_BytesEqual(Tag, ExpectedTag) then
  begin
    if Length(Result) > 0 then
      FillChar(Result[0], Length(Result), 0);
    SetLength(Result, 0);
    raise Exception.Create('C512: authentication failed — ciphertext tampered');
  end;
end;

// ── Convenience wrappers ───────────────────────────────────────────────────

function C512_EncryptWithNonce(const Key, AAD, Plaintext: TBytes): TBytes;
var
  Nonce, Inner: TBytes;
begin
  Nonce := RandomBytes(C512_NONCE_SIZE);
  Inner := C512_Encrypt(Key, Nonce, AAD, Plaintext);
  Result := ConcatBytes(Nonce, Inner);
end;

function C512_DecryptWithNonce(const Key, AAD, Data: TBytes): TBytes;
var
  Nonce, Inner: TBytes;
begin
  if Length(Data) < C512_NONCE_SIZE + C512_TAG_SIZE then
    raise Exception.Create('C512: data too short (missing nonce+tag)');
  Nonce := SliceBytes(Data, 0, C512_NONCE_SIZE);
  Inner := SliceBytes(Data, C512_NONCE_SIZE, Length(Data) - C512_NONCE_SIZE);
  Result := C512_Decrypt(Key, Nonce, AAD, Inner);
end;

end.
