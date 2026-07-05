package com.adwarden.di

import android.content.Context
import androidx.room.Room
import com.adwarden.data.db.AdwardenDatabase
import com.adwarden.data.db.AppRuleDao
import com.adwarden.data.db.FilterDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DataModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AdwardenDatabase =
        Room.databaseBuilder(context, AdwardenDatabase::class.java, "adwarden.db")
            .build()

    @Provides
    fun provideFilterDao(db: AdwardenDatabase): FilterDao = db.filterDao()

    @Provides
    fun provideAppRuleDao(db: AdwardenDatabase): AppRuleDao = db.appRuleDao()
}
