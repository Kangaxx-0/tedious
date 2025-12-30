import { assert } from 'chai';
import Login7Payload from '../../src/login7-payload';

describe('Login7Payload', function() {
  describe('#toBuffer', function() {

    describe('for a login payload with a password', function() {
      it('generates the expected data', function() {
        const payload = new Login7Payload({
          tdsVersion: 0x72090002,
          packetSize: 1024,
          clientProgVer: 0,
          clientPid: 12345,
          connectionId: 0,
          clientTimeZone: 120,
          clientLcid: 0x00000409
        });

        payload.hostname = 'example.com';
        payload.userName = 'user';
        payload.password = 'pw';
        payload.appName = 'app';
        payload.serverName = 'server';
        payload.language = 'lang';
        payload.database = 'db';
        payload.libraryName = 'Tedious';
        payload.attachDbFile = 'c:\\mydbfile.mdf';
        payload.changePassword = 'new_pw';

        const data = payload.toBuffer();

        const expectedLength =
          4 + // Length
          32 + // Variable
          2 +
          2 +
          2 * payload.hostname.length +
          2 +
          2 +
          2 * payload.userName.length +
          2 +
          2 +
          2 * payload.password.length +
          2 +
          2 +
          2 * payload.appName.length +
          2 +
          2 +
          2 * payload.serverName.length +
          2 +
          2 +
          2 * 0 + // Reserved
          2 +
          2 +
          2 * payload.libraryName.length +
          2 +
          2 +
          2 * payload.language.length +
          2 +
          2 +
          2 * payload.database.length +
          6 + // ClientID
          2 +
          2 +
          2 * 0 + // No SSPI given
          2 +
          2 +
          2 * payload.attachDbFile.length +
          2 +
          2 +
          2 * payload.changePassword.length +
          4 + // cbSSPILong
          4 + // Extension offset (always written for Fabric compatibility)
          1; // FEATURE_EXT_TERMINATOR (no UTF8_SUPPORT for TDS 7.2)

        assert.lengthOf(data, expectedLength);

        const passwordStart = data.readUInt16LE(4 + 32 + 2 * 4);
        const passwordEnd = passwordStart + 2 * payload.password.length;
        const passwordExpected = Buffer.from([0xa2, 0xa5, 0xd2, 0xa5]);

        assert.deepEqual(data.slice(passwordStart, passwordEnd), passwordExpected);
      });
    });

    describe('for a login payload with SSPI data', function() {
      it('generates the expected data', function() {
        const payload = new Login7Payload({
          tdsVersion: 0x72090002,
          packetSize: 1024,
          clientProgVer: 0,
          clientPid: 12345,
          connectionId: 0,
          clientTimeZone: 120,
          clientLcid: 0x00000409
        });

        payload.hostname = 'example.com';
        payload.appName = 'app';
        payload.serverName = 'server';
        payload.language = 'lang';
        payload.database = 'db';
        payload.libraryName = 'Tedious';
        payload.attachDbFile = 'c:\\mydbfile.mdf';
        payload.changePassword = 'new_pw';
        payload.sspi = Buffer.from([0xa0, 0xa1, 0xa2, 0xa5, 0xd2, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9]);

        const data = payload.toBuffer();

        const expectedLength =
          4 + // Length
          32 + // Variable
          2 + 2 + (2 * payload.hostname.length) +
          2 + 2 + (2 * 0) +
          2 + 2 + (2 * 0) +
          2 + 2 + (2 * payload.appName.length) +
          2 + 2 + (2 * payload.serverName.length) +
          2 + 2 + (2 * 0) + // Reserved
          2 + 2 + (2 * payload.libraryName.length) +
          2 + 2 + (2 * payload.language.length) +
          2 + 2 + (2 * payload.database.length) +
          6 +
          2 + 2 + payload.sspi.length + // NTLM
          2 + 2 + (2 * payload.attachDbFile.length) +
          2 + 2 + (2 * payload.changePassword.length) +
          4 + // cbSSPILong
          4 + // Extension offset (always written for Fabric compatibility)
          1; // FEATURE_EXT_TERMINATOR (no UTF8_SUPPORT for TDS 7.2)

        assert.lengthOf(data, expectedLength);
      });
    });

    describe('for a login payload with active directory authentication', function() {
      it('generates the expected data', function() {
        const payload = new Login7Payload({
          tdsVersion: 0x74000004,
          packetSize: 1024,
          clientProgVer: 0,
          clientPid: 12345,
          connectionId: 0,
          clientTimeZone: 120,
          clientLcid: 0x00000409
        });

        payload.hostname = 'example.com';
        payload.appName = 'app';
        payload.serverName = 'server';
        payload.language = 'lang';
        payload.database = 'db';
        payload.libraryName = 'Tedious';
        payload.attachDbFile = 'c:\\mydbfile.mdf';
        payload.changePassword = 'new_pw';
        payload.fedAuth = {
          type: 'ADAL',
          echo: true,
          workflow: 'default'
        };

        const data = payload.toBuffer();

        const expectedLength =
          4 + // Length
          32 + // Fixed data
          // Variable
          2 + 2 + (2 * payload.hostname.length) +
          2 + 2 + 2 * 0 + // Username
          2 + 2 + 2 * 0 + // Password
          2 + 2 + (2 * payload.appName.length) +
          2 + 2 + (2 * payload.serverName.length) +
          2 + 2 + 4 +
          2 + 2 + (2 * payload.libraryName.length) +
          2 + 2 + (2 * payload.language.length) +
          2 + 2 + (2 * payload.database.length) +
          6 + // ClientID
          2 + 2 + (2 * payload.attachDbFile.length) +
          2 + 2 + (2 * payload.changePassword.length) +
          4 + // cbSSPILong
          4 + // Extension offset
          1 + (1 + 4 + 1) + (1 + 4 + 1) + 1; // Feature ext - v7.4 includes UTF8_SUPPORT unlike prior versions

        assert.lengthOf(data, expectedLength);
      });
    });

    describe('for a login payload with token based authentication', function() {
      it('generates the expected data', function() {
        const token = 'validToken';

        const payload = new Login7Payload({
          tdsVersion: 0x74000004,
          packetSize: 1024,
          clientProgVer: 0,
          clientPid: 12345,
          connectionId: 0,
          clientTimeZone: 120,
          clientLcid: 0x00000409
        });

        payload.hostname = 'example.com';
        payload.appName = 'app';
        payload.serverName = 'server';
        payload.language = 'lang';
        payload.database = 'db';
        payload.libraryName = 'Tedious';
        payload.attachDbFile = 'c:\\mydbfile.mdf';
        payload.changePassword = 'new_pw';
        payload.fedAuth = {
          type: 'SECURITYTOKEN',
          echo: true,
          fedAuthToken: token
        };
        const data = payload.toBuffer();

        const expectedLength =
          4 + // Length
          32 + // Fixed data
          // Variable
          2 + 2 + (2 * payload.hostname.length) +
          2 + 2 + 2 * 0 + // Username
          2 + 2 + 2 * 0 + // Password
          2 + 2 + (2 * payload.appName.length) +
          2 + 2 + (2 * payload.serverName.length) +
          2 + 2 + 4 +
          2 + 2 + (2 * payload.libraryName.length) +
          2 + 2 + (2 * payload.language.length) +
          2 + 2 + (2 * payload.database.length) +
          6 + // ClientID
          2 + 2 + (2 * payload.attachDbFile.length) +
          2 + 2 + (2 * payload.changePassword.length) +
          4 + // cbSSPILong
          4 + // Extension offset
          (1 + 4 + 1 + 4 + (token.length * 2)) + // SECURITYTOKEN feature
          (1 + 4 + 1) + // UTF8_SUPPORT feature
          1; // Terminator

        assert.lengthOf(data, expectedLength);
      });
    });

    describe('for a fabric login payload with active directory authentication', function() {
      it('generates the expected data', function() {
        const payload = new Login7Payload({
          tdsVersion: 0x74000004,
          packetSize: 1024,
          clientProgVer: 0,
          clientPid: 12345,
          connectionId: 0,
          clientTimeZone: 120,
          clientLcid: 0x00000409,
          isFabric: true,
        } as any);

        payload.hostname = 'example.com';
        payload.appName = 'app';
        payload.serverName = 'server';
        payload.language = 'lang';
        payload.database = 'db';
        payload.libraryName = 'Tedious';
        payload.attachDbFile = 'c:\\mydbfile.mdf';
        payload.changePassword = 'new_pw';
        payload.fedAuth = {
          type: 'ADAL',
          echo: true,
          workflow: 'default'
        };

        const data = payload.toBuffer();

        const expectedLength =
          4 + // Length
          32 + // Fixed data
          // Variable
          2 + 2 + (2 * payload.hostname.length) +
          2 + 2 + 2 * 0 + // Username
          2 + 2 + 2 * 0 + // Password
          2 + 2 + (2 * payload.appName.length) +
          2 + 2 + (2 * payload.serverName.length) +
          2 + 2 + 4 +
          2 + 2 + (2 * payload.libraryName.length) +
          2 + 2 + (2 * payload.language.length) +
          2 + 2 + (2 * payload.database.length) +
          6 + // ClientID
          2 + 2 + (2 * payload.attachDbFile.length) +
          2 + 2 + (2 * payload.changePassword.length) +
          4 + // cbSSPILong
          4 + // Extension offset
          1 + (1 + 4 + 1) + (1 + 4 + 1) + 1; // Feature ext - v7.4 includes UTF8_SUPPORT unlike prior versions

        assert.lengthOf(data, expectedLength);
      });
    });

    describe('FeatureExtensions position (Fabric compatibility)', function() {
      it('writes extension data at the END of the packet, after all variable data', function() {
        const payload = new Login7Payload({
          tdsVersion: 0x74000004,
          packetSize: 1024,
          clientProgVer: 0,
          clientPid: 12345,
          connectionId: 0,
          clientTimeZone: 120,
          clientLcid: 0x00000409
        });

        payload.hostname = 'testhost';
        payload.appName = 'testapp';
        payload.serverName = 'testserver';
        payload.database = 'testdb';
        payload.libraryName = 'Tedious';

        const data = payload.toBuffer();

        // The ibExtension field is at offset 56 in the fixed header (after ibServerName/cchServerName)
        // Fixed header layout up to ibExtension:
        // 0-3: Length, 4-7: TDSVersion, 8-11: PacketSize, 12-15: ClientProgVer,
        // 16-19: ClientPID, 20-23: ConnectionID, 24: OptionFlags1, 25: OptionFlags2,
        // 26: TypeFlags, 27: OptionFlags3, 28-31: ClientTimZone, 32-35: ClientLCID,
        // 36-37: ibHostName, 38-39: cchHostName, 40-41: ibUserName, 42-43: cchUserName,
        // 44-45: ibPassword, 46-47: cchPassword, 48-49: ibAppName, 50-51: cchAppName,
        // 52-53: ibServerName, 54-55: cchServerName, 56-57: ibExtension
        const extensionOffset = data.readUInt16LE(56);

        // Calculate expected offset - extensions should be after all variable data
        const fixedDataSize = 94;
        const variableDataSize =
          2 * payload.hostname.length +
          2 * payload.appName.length +
          2 * payload.serverName.length +
          2 * payload.libraryName.length +
          2 * payload.database.length;

        const expectedExtensionOffset = fixedDataSize + variableDataSize;

        // Verify extensions are written at the expected position (after all variable data)
        assert.equal(extensionOffset, expectedExtensionOffset,
                     'Extension offset should point to position after all variable data');

        // Verify the last byte of the packet is the FEATURE_EXT_TERMINATOR (0xFF)
        assert.equal(data[data.length - 1], 0xFF,
                     'Last byte should be FEATURE_EXT_TERMINATOR');
      });
    });
  });
});
