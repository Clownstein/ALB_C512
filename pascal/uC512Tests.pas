unit uC512Tests;

{
  uC512Tests — Known-Answer Tests and Self-Test for ALB_C512 (C512).

  Run SelfTest to verify:
    1. Encrypt/decrypt round-trip for various message sizes.
    2. AAD binding (decrypt fails if AAD differs).
    3. Tag authentication (tampered ciphertext is rejected).
    4. Empty plaintext/AAD edge cases.
}

interface

uses
  System.SysUtils, System.Classes, uC512Cipher;

type
  TC512TestResult = record
    Passed: Boolean;
    Message: string;
  end;

function C512_SelfTest: TC512TestResult;
function C512_GenerateTestVectors: string;  // Returns JSON

implementation

uses
  System.JSON;

// ── Test helpers ───────────────────────────────────────────────────────────

function MakeKey(FillByte: Byte): TBytes;
var
  I: Integer;
begin
  SetLength(Result, C512_KEY_SIZE);
  for I := 0 to C512_KEY_SIZE - 1 do
    Result[I] := FillByte;
end;

function MakeSequentialKey: TBytes;
var
  I: Integer;
begin
  SetLength(Result, C512_KEY_SIZE);
  for I := 0 to C512_KEY_SIZE - 1 do
    Result[I] := Byte(I);
end;

function MakeNonce(FillByte: Byte): TBytes;
var
  I: Integer;
begin
  SetLength(Result, C512_NONCE_SIZE);
  for I := 0 to C512_NONCE_SIZE - 1 do
    Result[I] := FillByte;
end;

function MakeSequentialNonce: TBytes;
var
  I: Integer;
begin
  SetLength(Result, C512_NONCE_SIZE);
  for I := 0 to C512_NONCE_SIZE - 1 do
    Result[I] := Byte(I);
end;

function MakeData(Size: Integer; FillByte: Byte): TBytes;
begin
  SetLength(Result, Size);
  if Size > 0 then
    FillChar(Result[0], Size, FillByte);
end;

function BytesToHex(const B: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Length(B) - 1 do
    Result := Result + IntToHex(B[I], 2);
  Result := LowerCase(Result);
end;

// ── Self-Test ──────────────────────────────────────────────────────────────

function C512_SelfTest: TC512TestResult;
var
  Key, Nonce, AAD, Plaintext, Ciphertext, Decrypted: TBytes;
  Tampered: TBytes;
  Failed: Boolean;
begin
  Result.Passed := False;
  Result.Message := '';

  try
    // Test 1: Empty plaintext, empty AAD
    Key := MakeSequentialKey;
    Nonce := MakeSequentialNonce;
    Ciphertext := C512_Encrypt(Key, Nonce, nil, nil);
    if Length(Ciphertext) <> C512_TAG_SIZE then
    begin
      Result.Message := 'Test 1 failed: expected tag-only output for empty plaintext';
      Exit;
    end;
    if BytesToHex(Ciphertext) <> '5caf3e55cecbb343fdefec652374380b65fe9305051381cc3e5a42013f7b5780' then
    begin
      Result.Message := 'Test 1 failed: known-answer tag mismatch';
      Exit;
    end;
    Decrypted := C512_Decrypt(Key, Nonce, nil, Ciphertext);
    if Length(Decrypted) <> 0 then
    begin
      Result.Message := 'Test 1 failed: expected empty decryption result';
      Exit;
    end;

    // Test 2: 64-byte plaintext with 64-byte AAD
    Plaintext := MakeData(64, $55);
    AAD := MakeData(64, $AA);
    Ciphertext := C512_Encrypt(Key, Nonce, AAD, Plaintext);
    if Length(Ciphertext) <> 64 + C512_TAG_SIZE then
    begin
      Result.Message := 'Test 2 failed: unexpected ciphertext length';
      Exit;
    end;
    if BytesToHex(Ciphertext) <> '8a188235724066c53e70e5bfa6218903c8864f46c34651d41208d97f5cfbf5f8b63484db55822117e1d5f1dbd584b8bd7ec5f00b720b9dcd3b6f021c7674cb754aa2cc17ba33593528c5c4dc309e75f959156e502ab2afc9e124ce65c3edca9e' then
    begin
      Result.Message := 'Test 2 failed: known-answer ciphertext/tag mismatch';
      Exit;
    end;
    Decrypted := C512_Decrypt(Key, Nonce, AAD, Ciphertext);
    if not C512_BytesEqual(Decrypted, Plaintext) then
    begin
      Result.Message := 'Test 2 failed: decrypted plaintext does not match';
      Exit;
    end;

    // Test 3: Canonical non-aligned plaintext
    Plaintext := TEncoding.UTF8.GetBytes('Hello, ALB_C512 encryption test!!!');
    Ciphertext := C512_Encrypt(Key, Nonce, nil, Plaintext);
    if BytesToHex(Ciphertext) <> 'eb279c7b30b3fc2288f6736f48c43e40eef4680ca3e34e9aa77d86fe41e855a6d7488479702a655740757d33575e838272f1373a773cf863d59d0a4b2b0b7ccc7449' then
    begin
      Result.Message := 'Test 3 failed: known-answer ciphertext/tag mismatch';
      Exit;
    end;
    Decrypted := C512_Decrypt(Key, Nonce, nil, Ciphertext);
    if not C512_BytesEqual(Decrypted, Plaintext) then
    begin
      Result.Message := 'Test 3 failed: non-aligned plaintext mismatch';
      Exit;
    end;

    // Test 4: Tampered ciphertext should fail
    Plaintext := MakeData(64, $55);
    AAD := MakeData(64, $AA);
    Ciphertext := C512_Encrypt(Key, Nonce, AAD, Plaintext);
    Tampered := Copy(Ciphertext, 0, Length(Ciphertext));
    Tampered[0] := Tampered[0] xor $FF;
    Failed := False;
    try
      C512_Decrypt(Key, Nonce, AAD, Tampered);
    except
      on E: Exception do
        Failed := True;
    end;
    if not Failed then
    begin
      Result.Message := 'Test 4 failed: tampered ciphertext was not rejected';
      Exit;
    end;

    // Test 5: Wrong AAD should fail
    Failed := False;
    try
      C512_Decrypt(Key, Nonce, MakeData(64, $BB), Ciphertext);
    except
      on E: Exception do
        Failed := True;
    end;
    if not Failed then
    begin
      Result.Message := 'Test 5 failed: wrong AAD was not rejected';
      Exit;
    end;

    // Test 6: Large plaintext (256 bytes)
    Plaintext := MakeData(256, $42);
    Ciphertext := C512_Encrypt(Key, Nonce, nil, Plaintext);
    Decrypted := C512_Decrypt(Key, Nonce, nil, Ciphertext);
    if not C512_BytesEqual(Decrypted, Plaintext) then
    begin
      Result.Message := 'Test 6 failed: large plaintext mismatch';
      Exit;
    end;

    // Test 7: Convenience wrappers (auto-nonce)
    Plaintext := MakeData(64, $55);
    AAD := MakeData(32, $CC);
    Ciphertext := C512_EncryptWithNonce(Key, AAD, Plaintext);
    if Length(Ciphertext) <> C512_NONCE_SIZE + 64 + C512_TAG_SIZE then
    begin
      Result.Message := 'Test 7 failed: unexpected output length from EncryptWithNonce';
      Exit;
    end;
    Decrypted := C512_DecryptWithNonce(Key, AAD, Ciphertext);
    if not C512_BytesEqual(Decrypted, Plaintext) then
    begin
      Result.Message := 'Test 7 failed: convenience wrapper round-trip mismatch';
      Exit;
    end;

    Result.Passed := True;
    Result.Message := 'All C512 self-tests passed (7/7)';

  except
    on E: Exception do
    begin
      Result.Passed := False;
      Result.Message := 'Exception during self-test: ' + E.Message;
    end;
  end;
end;

// ── Test Vector Generation (JSON) ──────────────────────────────────────────

function C512_GenerateTestVectors: string;
var
  JSON: TJSONArray;
  Key, Nonce, Plaintext: TBytes;

  procedure AddVector(const Name: string; const K, N, A, P: TBytes);
  var
    CT: TBytes;
    V: TJSONObject;
  begin
    CT := C512_Encrypt(K, N, A, P);
    V := TJSONObject.Create;
    V.AddPair('name', Name);
    V.AddPair('key', BytesToHex(K));
    V.AddPair('nonce', BytesToHex(N));
    V.AddPair('aad', BytesToHex(A));
    V.AddPair('plaintext', BytesToHex(P));
    V.AddPair('ciphertext_tag', BytesToHex(CT));
    JSON.AddElement(V);
  end;

begin
  JSON := TJSONArray.Create;
  try
    Key := MakeSequentialKey;
    Nonce := MakeSequentialNonce;

    AddVector('empty_plaintext_empty_aad', Key, Nonce, nil, nil);

    AddVector('64B_plaintext_64B_aad', Key, Nonce,
      MakeData(64, $AA), MakeData(64, $55));

    Plaintext := TEncoding.UTF8.GetBytes('Hello, ALB_C512 encryption test!!!');
    AddVector('37B_plaintext_no_aad', Key, Nonce, nil, Plaintext);

    AddVector('single_byte', Key, Nonce, nil, MakeData(1, $FF));

    AddVector('two_blocks_with_aad', Key, Nonce,
      MakeData(33, $DD), MakeData(128, $EE));

    AddVector('zero_key', MakeKey(0), Nonce, MakeData(16, $11), MakeData(32, $22));

    AddVector('empty_aad_with_plaintext', Key, Nonce, nil, MakeData(64, $55));

    AddVector('nonempty_aad_empty_plaintext', Key, Nonce,
      MakeData(64, $AA), nil);

    AddVector('exact_boundary_65B', Key, Nonce, nil, MakeData(65, $77));

    Result := JSON.Format(2);
  finally
    JSON.Free;
  end;
end;

end.
