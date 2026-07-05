package com.adwarden.data

import com.adwarden.data.db.AppRule
import com.adwarden.data.db.AppRuleDao
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Owns per-app firewall rules. A row is kept only while an app has a
 * non-default policy; setting it back to allow-everywhere removes the row.
 */
@Singleton
class AppRuleRepository @Inject constructor(
    private val appRuleDao: AppRuleDao,
) {
    val rules: Flow<List<AppRule>> = appRuleDao.rules()

    suspend fun rulesOnce(): List<AppRule> = appRuleDao.rulesOnce()

    suspend fun setPolicy(packageName: String, uid: Int, allowWifi: Boolean, allowCellular: Boolean) {
        if (allowWifi && allowCellular) {
            appRuleDao.deleteByPackage(packageName)
        } else {
            appRuleDao.upsert(AppRule(packageName, uid, allowWifi, allowCellular))
        }
    }
}
