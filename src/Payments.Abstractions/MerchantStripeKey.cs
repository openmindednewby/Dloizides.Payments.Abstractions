namespace Payments.AspNetCore.Merchant;

/// <summary>Shape checks for a merchant's own Stripe credentials, and the last-4 display hint.</summary>
public static class MerchantStripeKey
{
  /// <summary>Prefix of every Stripe secret key.</summary>
  public const string SecretKeyPrefix = "sk_";

  /// <summary>Prefix of every Stripe webhook signing secret.</summary>
  public const string WebhookSecretPrefix = "whsec_";

  /// <summary>Shorter than this is a typo, not a Stripe key.</summary>
  public const int MinSecretLength = 12;

  /// <summary>How many trailing characters an admin UI may display.</summary>
  public const int Last4Length = 4;

  /// <summary>True when <paramref name="secretKey"/> has the shape of a Stripe secret key.</summary>
  public static bool IsWellFormedSecretKey(string? secretKey) => HasShape(secretKey, SecretKeyPrefix);

  /// <summary>True when <paramref name="webhookSecret"/> has the shape of a Stripe webhook secret.</summary>
  public static bool IsWellFormedWebhookSecret(string? webhookSecret) =>
      HasShape(webhookSecret, WebhookSecretPrefix);

  /// <summary>Returns the last four characters of <paramref name="secretKey"/>.</summary>
  public static string Last4Of(string secretKey)
  {
    ArgumentNullException.ThrowIfNull(secretKey);
    return secretKey.Length >= Last4Length ? secretKey[^Last4Length..] : secretKey;
  }

  private static bool HasShape(string? value, string prefix)
  {
    if (string.IsNullOrWhiteSpace(value)) return false;

    var trimmed = value.Trim();
    return trimmed.StartsWith(prefix, StringComparison.Ordinal)
        && trimmed.Length >= MinSecretLength
        && !trimmed.Any(char.IsWhiteSpace);
  }
}
