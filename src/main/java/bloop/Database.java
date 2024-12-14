package bloop;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

interface BlockStore {
    void putBlock(byte[] key, byte[] value );
    byte[] getBlock(byte[] key);
    void deleteBlock(byte[] key);
}

public class Database {
    private String dbPath;

    public Database(String dbPath) {
        this.dbPath = dbPath;
    }

    public void initialize() {
        try {
            File dbFile = new File(this.dbPath);
            boolean databaseExists = dbFile.exists();
            if(databaseExists) {
                System.out.println(String.format("Database at path %s already exists", this.dbPath));
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        String dbUrl = "jdbc:sqlite:" + this.dbPath;

        try (
            Connection conn = DriverManager.getConnection(dbUrl);
        ) {
            String createTableSQL = """
                CREATE TABLE user(
                    id INTEGER PRIMARY KEY NOT NULL,
                    did TEXT NOT NULL,
                    handle TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    signing_key TEXT NOT NULL
                );
                """;
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createTableSQL);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}