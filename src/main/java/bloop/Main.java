package bloop;


import picocli.CommandLine;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello World!");
        int exitCode = new CommandLine(new App())
            .addSubcommand("init", new InitCommand())
            .addSubcommand("user", new UserCommand())
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
                description = "Initialize the application."
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

        @Override
        public void run() {
            System.out.printf("User created with DID: %s and Handle: %s%n", did, handle);
        }
    }
}
