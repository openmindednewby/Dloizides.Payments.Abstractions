using Payments.AspNetCore.Merchant;

namespace Payments.Abstractions.Tests;

public sealed class MerchantStripeKeyTests
{
  [Theory]
  [InlineData("sk_test_Ef12")]
  [InlineData("sk_live_Ef12")]
  [InlineData("  sk_live_Ef12  ")]
  public void IsWellFormedSecretKey_WithStripeSecretKey_ReturnsTrue(string key)
  {
    var result = MerchantStripeKey.IsWellFormedSecretKey(key);

    Assert.True(result);
  }

  [Theory]
  [InlineData("pk_test_Ef12")]
  [InlineData("sk_short")]
  [InlineData("sk_test_E f12")]
  [InlineData("")]
  [InlineData(null)]
  public void IsWellFormedSecretKey_WithNonSecretKeyValue_ReturnsFalse(string? key)
  {
    var result = MerchantStripeKey.IsWellFormedSecretKey(key);

    Assert.False(result);
  }

  [Theory]
  [InlineData("whsec_fixture", true)]
  [InlineData("sk_test_Ef12", false)]
  public void IsWellFormedWebhookSecret_WithCandidateValue_ReportsShape(string secret, bool expected)
  {
    var result = MerchantStripeKey.IsWellFormedWebhookSecret(secret);

    Assert.Equal(expected, result);
  }

  [Fact]
  public void Last4Of_WithLongKey_ReturnsTrailingFour()
  {
    var key = "sk_test_WXYZ";

    var last4 = MerchantStripeKey.Last4Of(key);

    Assert.Equal("WXYZ", last4);
  }

  [Fact]
  public void Last4Of_WithShortValue_ReturnsWholeValue()
  {
    var value = "abc";

    var last4 = MerchantStripeKey.Last4Of(value);

    Assert.Equal("abc", last4);
  }
}
