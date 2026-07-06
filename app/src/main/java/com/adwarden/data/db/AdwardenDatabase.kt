package com.adwarden.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

class Converters {
    @TypeConverter
    fun formatToString(format: FilterFormat): String = format.name

    @TypeConverter
    fun stringToFormat(value: String): FilterFormat = FilterFormat.valueOf(value)
}

@Database(
    entities = [FilterSubscription::class, CustomRule::class, AppRule::class],
    version = 2,
    exportSchema = true,
)
@TypeConverters(Converters::class)
abstract class AdwardenDatabase : RoomDatabase() {
    abstract fun filterDao(): FilterDao
    abstract fun appRuleDao(): AppRuleDao
}
