package com.adwarden.di

import android.content.Context
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.adwarden.data.db.AdwardenDatabase
import com.adwarden.data.db.AppRuleDao
import com.adwarden.data.db.FilterDao
import com.adwarden.data.db.StatsDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

// v2 adds AppRule.inspectTls (per-app TLS interception opt-in, P2). Defined at
// file scope, not inside the @Module — Dagger's superficial validation NPEs on
// an anonymous-object field of a module.
private val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE app_rule ADD COLUMN inspectTls INTEGER NOT NULL DEFAULT 0")
    }
}

// v3 adds the persistent daily-aggregate tables (P3-3). The CREATE TABLE text must
// match Room's generated schema exactly (see app/schemas/.../3.json) or the
// open-time identity check throws.
private val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `daily_stat` (" +
                "`dateEpochDay` INTEGER NOT NULL, " +
                "`packets` INTEGER NOT NULL DEFAULT 0, " +
                "`bytes` INTEGER NOT NULL DEFAULT 0, " +
                "`tcpPackets` INTEGER NOT NULL DEFAULT 0, " +
                "`dnsQueries` INTEGER NOT NULL DEFAULT 0, " +
                "`blocked` INTEGER NOT NULL DEFAULT 0, " +
                "PRIMARY KEY(`dateEpochDay`))",
        )
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `blocked_tally` (" +
                "`dateEpochDay` INTEGER NOT NULL, " +
                "`kind` TEXT NOT NULL, " +
                "`key` TEXT NOT NULL, " +
                "`count` INTEGER NOT NULL DEFAULT 0, " +
                "PRIMARY KEY(`dateEpochDay`, `kind`, `key`))",
        )
    }
}

// v4 adds the scriptlet resource pack table (P4-3). CREATE TABLE must match Room's
// generated schema exactly (see app/schemas/.../4.json) or the identity check throws.
private val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `scriptlet_pack` (" +
                "`id` TEXT NOT NULL, " +
                "`name` TEXT NOT NULL, " +
                "`url` TEXT NOT NULL, " +
                "`enabled` INTEGER NOT NULL, " +
                "`etag` TEXT, " +
                "`lastModified` TEXT, " +
                "`lastSyncMs` INTEGER NOT NULL, " +
                "PRIMARY KEY(`id`))",
        )
    }
}

@Module
@InstallIn(SingletonComponent::class)
object DataModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AdwardenDatabase =
        Room.databaseBuilder(context, AdwardenDatabase::class.java, "adwarden.db")
            .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
            .build()

    @Provides
    fun provideFilterDao(db: AdwardenDatabase): FilterDao = db.filterDao()

    @Provides
    fun provideAppRuleDao(db: AdwardenDatabase): AppRuleDao = db.appRuleDao()

    @Provides
    fun provideStatsDao(db: AdwardenDatabase): StatsDao = db.statsDao()
}
