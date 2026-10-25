using System.Security.Cryptography;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Payments.AspNetCore.Merchant;
using Security.SecretProtector;

namespace Payments.Abstractions.Tests;

public sealed class MerchantStripeCredentialsTests
{
  private const string SecretKey = "sk_test_WXYZ";
  private const string WebhookSecret = "whsec_fixture";

  private static ISecretProtector ReversibleProtector()
  {
    var protector = Substitute.For<ISecretProtector>();
    protector.Protect(Arg.Any<string>()).Returns(call => "enc:" + call.Arg<string>());
    protector.Unprotect(Arg.Any<string>()).Returns(call => call.Arg<string>()["enc:".Length..]);
    return protector;
  }

  private static ISecretProtector ThrowingProtector(Exception error)
  {
    var protector = Substitute.For<ISecretProtector>();
    protector.Unprotect(Arg.Any<string>()).Throws(error);
    return protector;
  }

  [Fact]
  public void Protect_WithWellFormedKeys_StoresCiphertextAndLast4()
  {
    var protector = ReversibleProtector();

    var credentials = MerchantStripeCredentials.Protect(protector, "  sk_test_WXYZ", "whsec_fixture", paymentsEnabled: true);

    Assert.Equal("enc:sk_test_WXYZ", credentials.SecretKeyEnc);
    Assert.Equal("enc:whsec_fixture", credentials.WebhookSecretEnc);
    Assert.Equal("WXYZ", credentials.SecretKeyLast4);
    Assert.True(credentials.CanAcceptPayments);
  }

  [Fact]
  public void Protect_WithPublishableKey_ThrowsArgumentException()
  {
    var protector = ReversibleProtector();

    var act = () => MerchantStripeCredentials.Protect(protector, "pk_test_WXYZ", WebhookSecret, paymentsEnabled: true);

    var error = Assert.Throws<ArgumentException>(act);
    Assert.Equal("secretKey", error.ParamName);
  }

  [Fact]
  public void Protect_WithMalformedWebhookSecret_ThrowsArgumentException()
  {
    var protector = ReversibleProtector();

    var act = () => MerchantStripeCredentials.Protect(protector, SecretKey, "not-a-whsec", paymentsEnabled: true);

    var error = Assert.Throws<ArgumentException>(act);
    Assert.Equal("webhookSecret", error.ParamName);
  }

  [Fact]
  public void NotConfigured_WhenCreated_CannotAcceptPayments()
  {
    var credentials = MerchantStripeCredentials.NotConfigured();

    Assert.False(credentials.IsConfigured);
    Assert.False(credentials.CanAcceptPayments);
  }

  [Fact]
  public void CanAcceptPayments_WithConfiguredButDisabled_ReturnsFalse()
  {
    var credentials = MerchantStripeCredentials.Configured("enc:a", "enc:b", "WXYZ", paymentsEnabled: false);

    var canAccept = credentials.CanAcceptPayments;

    Assert.True(credentials.IsConfigured);
    Assert.False(canAccept);
  }

  [Fact]
  public void TryUnprotect_WithStoredCiphertext_ReturnsPlaintextSecrets()
  {
    var protector = ReversibleProtector();
    var credentials = MerchantStripeCredentials.Configured("enc:sk_test_WXYZ", "enc:whsec_fixture", "WXYZ", paymentsEnabled: true);

    var ok = credentials.TryUnprotect(protector, out var secrets);

    Assert.True(ok);
    Assert.Equal("sk_test_WXYZ", secrets!.SecretKey);
    Assert.Equal("whsec_fixture", secrets.WebhookSecret);
  }

  [Fact]
  public void TryUnprotect_WhenCiphertextFailsAuthentication_ReturnsFalse()
  {
    var protector = ThrowingProtector(new CryptographicException("tag mismatch"));
    var credentials = MerchantStripeCredentials.Configured("enc:a", "enc:b", "WXYZ", paymentsEnabled: true);

    var ok = credentials.TryUnprotect(protector, out var secrets);

    Assert.False(ok);
    Assert.Null(secrets);
  }

  [Fact]
  public void TryUnprotect_WhenTokenIsNotBase64_ReturnsFalse()
  {
    var protector = ThrowingProtector(new FormatException("not base64"));
    var credentials = MerchantStripeCredentials.Configured("enc:a", "enc:b", "WXYZ", paymentsEnabled: true);

    var ok = credentials.TryUnprotect(protector, out var secrets);

    Assert.False(ok);
    Assert.Null(secrets);
  }

  [Fact]
  public void TryUnprotect_WhenProtectorHasNoKey_ThrowsInvalidOperation()
  {
    var protector = ThrowingProtector(new InvalidOperationException("no key configured"));
    var credentials = MerchantStripeCredentials.Configured("enc:a", "enc:b", "WXYZ", paymentsEnabled: true);

    Action act = () => credentials.TryUnprotect(protector, out _);

    Assert.Throws<InvalidOperationException>(act);
  }

  [Fact]
  public void TryUnprotect_WhenNotConfigured_ReturnsFalseWithoutDecrypting()
  {
    var protector = Substitute.For<ISecretProtector>();
    var credentials = MerchantStripeCredentials.NotConfigured();

    var ok = credentials.TryUnprotect(protector, out _);

    Assert.False(ok);
    protector.DidNotReceive().Unprotect(Arg.Any<string>());
  }

  [Fact]
  public void ToString_WithSecrets_ShowsOnlyLast4()
  {
    var secrets = new MerchantStripeSecrets("sk_test_WXYZ", "whsec_fixture");

    var text = secrets.ToString();

    Assert.DoesNotContain("sk_test_WXYZ", text, StringComparison.Ordinal);
    Assert.DoesNotContain("whsec_fixture", text, StringComparison.Ordinal);
    Assert.EndsWith("WXYZ", text, StringComparison.Ordinal);
  }
}
