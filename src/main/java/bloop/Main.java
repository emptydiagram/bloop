package bloop;

import java.nio.file.*;
import java.io.IOException;
import java.security.Security;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;

public class Main {
    public static void main(String[] args) {
        int exitCode = new CommandLine(new App())
            .addSubcommand("init", new InitCommand())
            .addSubcommand("user", new UserCommand())
            .addSubcommand("util", new UtilCommand())
            .execute(args);
        System.exit(exitCode);
    }

    @CommandLine.Command(
            name = "bloop",
            mixinStandardHelpOptions = true,
            description = "A WIP bluesky PDS"
    )
    static class App {
    }

    @CommandLine.Command(
                name = "init",
                mixinStandardHelpOptions = true,
                description = "Initialize the database."
        )
    static class InitCommand implements Runnable {

        @Override
        public void run() {
            var db = new Database(StaticConfig.SQLITE_DB_PATH);
            db.initialize();
        }
    }

    @CommandLine.Command(
            name = "user",
            mixinStandardHelpOptions = true,
            description = "Manage users.",
            subcommands = {CreateUserCommand.class}
    )
    static class UserCommand {
    }

    @CommandLine.Command(
            name = "create",
            mixinStandardHelpOptions = true,
            description = "Create a new user with DID and handle."
    )
    static class CreateUserCommand implements Runnable {

        @CommandLine.Parameters(index = "0", description = "The DID of the user.")
        private String did;

        @CommandLine.Parameters(index = "1", description = "The handle of the user.")
        private String handle;

        private boolean validateHandle(String handle) {
            Pattern pattern = Pattern.compile("/^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$/");
            Matcher matcher = pattern.matcher(handle);
            return matcher.find();
        }

        @Override
        public void run() {
            System.out.println(this.validateHandle(this.handle));
            System.out.printf("User created with DID: %s and Handle: %s%n", did, handle);
        }
    }

    @CommandLine.Command(
            name = "util",
            mixinStandardHelpOptions = true,
            description = "Misc. utilities",
            subcommands = { KeyGenCommand.class, DisplayPubKeyCommand.class }
    )
    static class UtilCommand {
    }

    @CommandLine.Command(
            name = "keygen",
            mixinStandardHelpOptions = true,
            description = "Generate private key and output in PEM format"
    )
    static class KeyGenCommand implements Runnable {

        @CommandLine.Option(
            names = {"-k", "--key-type"},
            description = "Key type. 'k256' or 'p256'. Defaults to 'k256'.",
            defaultValue = "k256"
        )
        private String keyType;

        @CommandLine.Option(names = "--display-pubkey") boolean displayPubkey;

        private static final String KEY_TYPE_K256 = "secp256k1";
        private static final String KEY_TYPE_P256 = "prime256v1";


        @Override
        public void run() {
            Security.addProvider(new BouncyCastleProvider());

            this.keyType = this.keyType.toLowerCase();
            String curveName = null;
            if(this.keyType.equals("k256")) {
                curveName = KeyGenCommand.KEY_TYPE_K256;
            } else if (this.keyType.equals("p256")) {
                curveName = KeyGenCommand.KEY_TYPE_P256;
            } else {
                System.out.printf("Unrecognized key type: %s (Should be 'k256' or 'p256')\n", keyType);
                return;
            }
            var keyPair = DidHelper.generateKeyPair(curveName);
            System.out.println(DidHelper.convertKeyToPem(keyPair.getPrivate(), "PRIVATE KEY"));
            if(this.displayPubkey) {
                System.out.println(DidHelper.convertKeyToPem(keyPair.getPublic(), "PUBLIC KEY"));
            }
        }
    }

    @CommandLine.Command(
        name = "display-pubkey",
        mixinStandardHelpOptions = true,
        description = "Display public key PEM from private key PEM"
    )
    static class DisplayPubKeyCommand implements Runnable {

        @CommandLine.Parameters(index = "0", description = "Path to PEM file of private key.")
        private String pemPath;

        @Override
        public void run() {
            Security.addProvider(new BouncyCastleProvider());
            Path filePath = Paths.get(this.pemPath);
            try {
                String pemString = Files.readString(filePath);
                var publicKey = DidHelper.getPublicKeyFromPem(pemString);
                System.out.println(DidHelper.convertKeyToPem(publicKey, "PUBLIC KEY"));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

}
