unit uCryptoEngine;

{
  uCryptoEngine — Minimal C512 dispatch wrapper.

  Provides a small Encrypt/Decrypt interface for the packaged ALB_C512 units.

  Wire format for encrypted output:
    [AlgoTag(1)] [Nonce(variable)] [Ciphertext] [Tag(variable, if AEAD)]

  For C512:
    Nonce(32) || Ciphertext || Tag(32)
}

interface

uses
  System.SysUtils, System.Classes, uC512Cipher;

type
  ECryptoEngineError = class(Exception);
  TCipherAlgo = (caC512);

// ── High-level API ─────────────────────────────────────────────────────────

function CryptoEncrypt(
  const Key: TBytes;
  const Plaintext: TBytes;
  const AAD: TBytes;
  Algo: TCipherAlgo
): TBytes;

function CryptoDecrypt(
  const Key: TBytes;
  const Data: TBytes;
  const AAD: TBytes;
  Algo: TCipherAlgo
): TBytes;

// ── Key size lookup ────────────────────────────────────────────────────────

function GetRequiredKeySize(Algo: TCipherAlgo): Integer;

implementation

function CipherAlgoName(Algo: TCipherAlgo): string;
begin
  case Algo of
    caC512: Result := 'C512';
  else
    Result := 'unknown';
  end;
end;

// ── Key size lookup ────────────────────────────────────────────────────────

function GetRequiredKeySize(Algo: TCipherAlgo): Integer;
begin
  case Algo of
    caC512:       Result := C512_KEY_SIZE;
  else
    raise ECryptoEngineError.CreateFmt(
      'GetRequiredKeySize: algorithm %s not implemented',
      [CipherAlgoName(Algo)]);
  end;
end;

// ── Encrypt dispatch ───────────────────────────────────────────────────────

function CryptoEncrypt(
  const Key, Plaintext, AAD: TBytes;
  Algo: TCipherAlgo
): TBytes;
begin
  case Algo of
    caC512:
    begin
      Result := C512_EncryptWithNonce(Key, AAD, Plaintext);
    end;

  else
    raise ECryptoEngineError.CreateFmt(
      'CryptoEncrypt: algorithm %s not yet implemented',
      [CipherAlgoName(Algo)]);
  end;
end;

// ── Decrypt dispatch ───────────────────────────────────────────────────────

function CryptoDecrypt(
  const Key, Data, AAD: TBytes;
  Algo: TCipherAlgo
): TBytes;
begin
  case Algo of
    caC512:
    begin
      Result := C512_DecryptWithNonce(Key, AAD, Data);
    end;

  else
    raise ECryptoEngineError.CreateFmt(
      'CryptoDecrypt: algorithm %s not yet implemented',
      [CipherAlgoName(Algo)]);
  end;
end;

end.
