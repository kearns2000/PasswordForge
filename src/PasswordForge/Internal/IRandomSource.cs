namespace PasswordForge.Internal;

/// <summary>
/// Abstraction over random number generation for testability.
/// </summary>
internal interface IRandomSource
{
    int NextInt32(int maxExclusive);

    void Shuffle(Span<char> buffer);
}

/// <summary>
/// Cryptographically secure random source for production use.
/// </summary>
internal sealed class CryptographicRandomSource : IRandomSource
{
    public int NextInt32(int maxExclusive) =>
        System.Security.Cryptography.RandomNumberGenerator.GetInt32(maxExclusive);

    public void Shuffle(Span<char> buffer)
    {
        for (var i = buffer.Length - 1; i > 0; i--)
        {
            var j = NextInt32(i + 1);
            (buffer[i], buffer[j]) = (buffer[j], buffer[i]);
        }
    }
}
