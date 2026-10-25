using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Security.SecretProtector;

namespace Payments.AspNetCore.Merchant;

/// <summary>A merchant's own Stripe credentials, stored only as <see cref="ISecretProtector"/> ciphertext.</summary>
public sealed class MerchantStripeCredentials
{
  /// <summary>Ciphertext of the merchant's Stripe secret key.</summary>
  public string? SecretKeyEnc { get; private set; }

  /// <summary>Ciphertext of the merchant's webhook signing secret.</summary>
  public string? WebhookSecretEnc { get; private set; }

  /// <summary>Last four characters of the secret key; a display hint, never a secret.</summary>
  public string? SecretKeyLast4 { get; private set; }

  /// <summary>Whether the merchant has switched card payments on.</summary>
  public bool PaymentsEnabled { get; private set; }

  private MerchantStripeCredentials() { }

  private MerchantStripeCredentials(
      string? secretKeyEnc, string? webhookSecretEnc, string? secretKeyLast4, bool paymentsEnabled)
  {
    SecretKeyEnc = secretKeyEnc;
    WebhookSecretEnc = webhookSecretEnc;
    SecretKeyLast4 = secretKeyLast4;
    PaymentsEnabled = paymentsEnabled;
  }

  /// <summary>True when both ciphertexts are stored.</summary>
  public bool IsConfigured =>
      !string.IsNullOrWhiteSpace(SecretKeyEnc) && !string.IsNullOrWhiteSpace(WebhookSecretEnc);

  /// <summary>True when the merchant can take a card payment right now.</summary>
  public bool CanAcceptPayments => IsConfigured && PaymentsEnabled;

  /// <summary>No Stripe account connected and card payments off.</summary>
  public static MerchantStripeCredentials NotConfigured() =>
      new(secretKeyEnc: null, webhookSecretEnc: null, secretKeyLast4: null, paymentsEnabled: false);

  /// <summary>Rehydrates credentials from already-encrypted stored values.</summary>
  public static MerchantStripeCredentials Configured(
      string secretKeyEnc, string webhookSecretEnc, string secretKeyLast4, bool paymentsEnabled)
  {
    ArgumentException.ThrowIfNullOrWhiteSpace(secretKeyEnc);
    ArgumentException.ThrowIfNullOrWhiteSpace(webhookSecretEnc);
    ArgumentException.ThrowIfNullOrWhiteSpace(secretKeyLast4);
    return new(secretKeyEnc, webhookSecretEnc, secretKeyLast4, paymentsEnabled);
  }

  /// <summary>Checks the shape of plaintext keys, then encrypts them with <paramref name="protector"/>.</summary>
  public static MerchantStripeCredentials Protect(
      ISecretProtector protector, string secretKey, string webhookSecret, bool paymentsEnabled)
  {
    ArgumentNullException.ThrowIfNull(protector);
    if (!MerchantStripeKey.IsWellFormedSecretKey(secretKey))
      throw new ArgumentException("Not a Stripe secret key (sk_...).", nameof(secretKey));
    if (!MerchantStripeKey.IsWellFormedWebhookSecret(webhookSecret))
      throw new ArgumentException("Not a Stripe webhook signing secret (whsec_...).", nameof(webhookSecret));

    var key = secretKey.Trim();
    var hook = webhookSecret.Trim();
    return new(protector.Protect(key), protector.Protect(hook), MerchantStripeKey.Last4Of(key), paymentsEnabled);
  }

  /// <summary>Decrypts the stored secrets; false when unset, tampered or encrypted under another key.</summary>
  public bool TryUnprotect(ISecretProtector protector, [NotNullWhen(true)] out MerchantStripeSecrets? secrets)
  {
    ArgumentNullException.ThrowIfNull(protector);
    secrets = null;
    if (!IsConfigured) return false;

    try
    {
      secrets = new MerchantStripeSecrets(protector.Unprotect(SecretKeyEnc!), protector.Unprotect(WebhookSecretEnc!));
      return true;
    }
    catch (Exception ex) when (ex is CryptographicException or FormatException)
    {
      return false;
    }
  }
}
