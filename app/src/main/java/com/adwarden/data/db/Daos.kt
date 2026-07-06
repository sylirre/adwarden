package com.adwarden.data.db

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

@Dao
interface FilterDao {

    @Query("SELECT * FROM filter_subscription ORDER BY name")
    fun subscriptions(): Flow<List<FilterSubscription>>

    @Query("SELECT * FROM filter_subscription")
    suspend fun subscriptionsOnce(): List<FilterSubscription>

    @Query("SELECT COUNT(*) FROM filter_subscription")
    suspend fun subscriptionCount(): Int

    @Upsert
    suspend fun upsertSubscription(subscription: FilterSubscription)

    @Upsert
    suspend fun upsertSubscriptions(subscriptions: List<FilterSubscription>)

    @Query("UPDATE filter_subscription SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)

    // Conditional on the old URL so it never clobbers anything but the exact
    // superseded default; the stale validators are cleared with it.
    @Query(
        "UPDATE filter_subscription SET url = :newUrl, etag = NULL, lastModified = NULL " +
            "WHERE id = :id AND url = :oldUrl",
    )
    suspend fun migrateUrl(id: String, oldUrl: String, newUrl: String)

    @Query(
        "UPDATE filter_subscription SET etag = :etag, lastModified = :lastModified, " +
            "lastSyncMs = :syncedAt, ruleCount = :ruleCount WHERE id = :id",
    )
    suspend fun updateSyncMeta(
        id: String,
        etag: String?,
        lastModified: String?,
        syncedAt: Long,
        ruleCount: Int,
    )

    @Query("SELECT * FROM custom_rule ORDER BY createdMs DESC")
    fun customRules(): Flow<List<CustomRule>>

    @Query("SELECT * FROM custom_rule WHERE enabled = 1")
    suspend fun enabledCustomRules(): List<CustomRule>

    @Insert
    suspend fun insertCustomRule(rule: CustomRule): Long

    @Delete
    suspend fun deleteCustomRule(rule: CustomRule)
}

@Dao
interface AppRuleDao {

    @Query("SELECT * FROM app_rule")
    fun rules(): Flow<List<AppRule>>

    @Query("SELECT * FROM app_rule")
    suspend fun rulesOnce(): List<AppRule>

    @Upsert
    suspend fun upsert(rule: AppRule)

    @Query("DELETE FROM app_rule WHERE packageName = :packageName")
    suspend fun deleteByPackage(packageName: String)
}
