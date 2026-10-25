namespace Payments.AspNetCore.Merchant;

/// <summary>Decrypted merchant Stripe secrets; <see cref="ToString"/> never prints them.</summary>
public sealed record MerchantStripeSecrets(string SecretKey, string WebhookSecret)
{
  /// <inheritdoc />
  public override string ToString() =>
      $"MerchantStripeSecrets ***{MerchantStripeKey.Last4Of(SecretKey)}";
}
