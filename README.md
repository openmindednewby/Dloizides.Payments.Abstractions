# Dloizides.Payments.Abstractions

Stripe-free merchant payment value objects for domain (Core) projects: `MerchantStripeCredentials`, `MerchantStripeKey`, `MerchantStripeSecrets`.
Depends only on `Security.SecretProtector`; no ASP.NET Core, no Stripe.net.

```csharp
using Payments.AspNetCore.Merchant;

var credentials = MerchantStripeCredentials.Protect(protector, "sk_live_...", "whsec_...", paymentsEnabled: true);
```

The namespace stays `Payments.AspNetCore.Merchant`; `Dloizides.Payments.AspNetCore` 1.2.0+ references this package and forwards the types, so binaries built against 1.1.x keep working.

Publish: `./publish.ps1 -NoBump` (or `-Bump patch|minor|major`).
