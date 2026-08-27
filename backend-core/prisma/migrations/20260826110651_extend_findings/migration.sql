/*
  Warnings:

  - You are about to drop the column `primitive` on the `Finding` table. All the data in the column will be lost.
  - Added the required column `algorithm` to the `Finding` table without a default value. This is not possible if the table is not empty.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "filePath" TEXT NOT NULL,
    "lineNumber" INTEGER,
    "algorithm" TEXT NOT NULL,
    "library" TEXT,
    "usage" TEXT,
    "keySize" INTEGER,
    "quantumStatus" TEXT,
    "severity" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "recommendation" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_Finding" ("createdAt", "description", "filePath", "id", "lineNumber", "scanId", "severity") SELECT "createdAt", "description", "filePath", "id", "lineNumber", "scanId", "severity" FROM "Finding";
DROP TABLE "Finding";
ALTER TABLE "new_Finding" RENAME TO "Finding";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
