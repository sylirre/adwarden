package com.adwarden.di

import android.content.Context
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.adwarden.data.db.AdwardenDatabase
import com.adwarden.data.db.AppRuleDao
import com.adwarden.data.db.FilterDao
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

@Module
@InstallIn(SingletonComponent::class)
object DataModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AdwardenDatabase =
        Room.databaseBuilder(context, AdwardenDatabase::class.java, "adwarden.db")
            .addMigrations(MIGRATION_1_2)
            .build()

    @Provides
    fun provideFilterDao(db: AdwardenDatabase): FilterDao = db.filterDao()

    @Provides
    fun provideAppRuleDao(db: AdwardenDatabase): AppRuleDao = db.appRuleDao()
}
