using Infrastructure.Entitys;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Infrastructure.Helpers
{
    public class PasswordHasher
    {
        // The size of the salt.
        private const int SaltSize = 32;
        // Private key used in the HMAC-algorithm to create a hashed password together with the salt.

        /// <summary>
        /// Creates a instance of HMACSHA256 with the SecurityKey, then the salt is introduced to the HMAC-object.
        /// Converts the password to bytes and the HMACSHA256 algo is used to calculate the hashvalue.
        /// </summary>
        /// <param name="password">The input password from the user</param>
        /// <returns>Returns salt, hash as 64base-coded and SecurityKey as strings</returns>
        public static UserCredentialsEntity GenerateSecurePassword(string password)
        {
            try
            {
                byte[] salt = GenerateSalt();
                byte[] securityKey = Generate128BitKey();
                byte[] keyDerivation = CombineToKeyDerivation(salt, securityKey);

                var hmac = new HMACSHA256(keyDerivation);

                var hashedPassword = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

                return new UserCredentialsEntity
                {
                    Salt = Convert.ToBase64String(salt),
                    HashedPassword = Convert.ToBase64String(hashedPassword),
                    SecurityKey = Convert.ToBase64String(securityKey)
                };
            }
            catch (Exception ex) { Debug.Write(ex.Message); }
            return null!;
        }

        /// <summary>
        /// Validates a password against a already generated hashvalue
        /// Basicaly recreating the old password with the saved passwordhash, salt and securitykey.
        /// Creates a instance of the HMAC-algo with the SecurityKey as a key and the salt is assigned the HMAC-object, combined to key derivation.
        /// The password is converted to bytes and HMAC calculate the hash value.
        /// Lastely, the two hashvalues are compared against each other
        /// </summary>
        /// <param name="password">The input password from the user</param>
        /// <param name="savedPasswordHash">Stored hash</param>
        /// <param name="savedSalt">Stored Salting</param>
        /// <param name="savedSecurityKey">Stored security key</param>
        /// <returns>True if valid, else false</returns>
        public static bool ValidateSecurePassword(string password, string savedPasswordHash, string savedSalt, string savedSecurityKey)
        {
            try
            {
                byte[] hashBytes = Convert.FromBase64String(savedPasswordHash);
                byte[] saltBytes = Convert.FromBase64String(savedSalt);
                byte[] keyBytes = Convert.FromBase64String(savedSecurityKey);
                byte[] keyDerivation = CombineToKeyDerivation(saltBytes, keyBytes);

                var hmac = new HMACSHA256(keyDerivation);
                byte[] recreatePasswordByte = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

                return AreHashesEqual(hashBytes, recreatePasswordByte);
            }
            catch (Exception ex)
            {
                Debug.Write(ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Generates a random salt based on the SaltSize.
        /// </summary>
        /// <returns>A byte array of salt</returns>
        private static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            return salt;
        }

        /// <summary>
        /// Combines salt and securityKey arrays to create a key derivation using the range operator.
        /// </summary>
        /// <param name="salt">Byte array of the salt</param>
        /// <param name="securityKey">Byte array of the securitykey</param>
        /// <returns>The combinated arrays as key derivation</returns>
        private static byte[] CombineToKeyDerivation(byte[] salt, byte[] securityKey)
        {
            byte[] keyDerivation = [.. salt, .. securityKey];
            return keyDerivation;
        }

        /// <summary>
        /// Using a 128Bit (16Bytes) key here to generate a random key value.
        /// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512.-ctor?view=net-8.0
        /// </summary>
        /// <returns>Returns the random generated 128bit value, aka the key. </returns>
        private static byte[] Generate128BitKey()
        {
            byte[] key = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            return key;
        }

        /// <summary>
        /// Compares two hashvalues against each other. 
        /// First we controll the length of the two byte-arrays against each other, secondly we control the byte separately
        /// </summary>
        /// <param name="hash1">Represents the saved hash-value</param>
        /// <param name="hash2">Represents the new (input) hash-value</param>
        /// <returns>True if hashed are equal, else false</returns>
        private static bool AreHashesEqual(byte[] hash1, byte[] hash2)
        {
            if (hash1.Length != hash2.Length)
                return false;

            for (int i = 0; i < hash1.Length; i++)
            {
                if (hash1[i] != hash2[i])
                    return false;
            }

            return true;
        }
    }
}
