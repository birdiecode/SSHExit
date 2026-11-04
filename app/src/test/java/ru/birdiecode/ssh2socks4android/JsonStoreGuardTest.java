package ru.birdiecode.ssh2socks4android;

import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class JsonStoreGuardTest {
    private JSONObject schema() throws Exception {
        return new JSONObject().put("id", "").put("name", "").put("port", 22).put("enabled", true);
    }
    private JSONArray valid(String id) throws Exception {
        return new JSONArray().put(new JSONObject().put("id", id).put("name", "host"));
    }
    private void rejected(Runnable operation) {
        try { operation.run(); fail("Damaged data accepted"); }
        catch (JsonStoreGuard.StorageException expected) {
            assertFalse(expected.getMessage().contains("SECRET"));
        }
    }

    @Test public void malformedJsonCannotBeReplacedByAnEmptyCollection() throws Exception {
        MemoryPrefs prefs = new MemoryPrefs();
        String damaged = "[{\"id\":\"SECRET";
        prefs.edit().putString("data", damaged).putString("data.last_good", "[]").commit();
        JSONObject schema = schema();
        rejected(() -> JsonStoreGuard.read(prefs, "data", schema, "Test store"));
        rejected(() -> JsonStoreGuard.write(prefs, "data", new JSONArray(), schema, "Test store", "migrated"));
        assertEquals(damaged, prefs.getString("data", ""));
        assertEquals(damaged, prefs.getString("data.corrupt_first", ""));
        assertEquals("[]", prefs.getString("data.last_good", ""));
        assertFalse(prefs.contains("migrated"));
        assertFalse(AppLog.INSTANCE.render(AppLog.TRACE).contains("SECRET"));
    }

    @Test public void invalidRecordsAndTrailingDataBlockTheWholeCollection() throws Exception {
        for (String payload : new String[]{"[null]", "[1]", "[{}]",
                "[{\"id\":\"\"}]", "[{\"id\":7}]", "[{\"id\":\"x\"},{\"id\":\"x\"}]",
                "[{\"id\":\"x\",\"port\":\"22\"}]", "[{\"id\":\"x\",\"enabled\":null}]",
                "[{\"id\":\"x\",\"newerField\":true}]", "[] trailing",
                "[{\"id\":\"x\",\"port\":2147483648}]", "[{\"id\":\"x\",\"port\":1.5}]"}) {
            MemoryPrefs prefs = new MemoryPrefs();
            prefs.edit().putString("data", payload).commit();
            JSONObject schema = schema();
            rejected(() -> JsonStoreGuard.read(prefs, "data", schema, "Test store"));
            assertEquals(payload, prefs.getString("data", ""));
        }
    }

    @Test public void emptyAndLegacyRecordsAreValidAndWritesBackUpPreviousPayload() throws Exception {
        MemoryPrefs prefs = new MemoryPrefs();
        JSONObject schema = schema();
        assertEquals(0, JsonStoreGuard.read(prefs, "data", schema, "Test store").length());
        JsonStoreGuard.write(prefs, "data", valid("old"), schema, "Test store", null);
        assertEquals("[]", prefs.getString("data.last_good", ""));
        String previous = prefs.getString("data", "");
        JsonStoreGuard.write(prefs, "data", valid("new"), schema, "Test store", "migrated");
        assertEquals(previous, prefs.getString("data.last_good", ""));
        assertTrue(prefs.getBoolean("migrated", false));
        assertEquals("new", JsonStoreGuard.read(prefs, "data", schema, "Test store").getJSONObject(0).getString("id"));
    }

    @Test public void firstCorruptSnapshotIsNotOverwrittenByAnotherFailure() throws Exception {
        MemoryPrefs prefs = new MemoryPrefs();
        JSONObject schema = schema();
        prefs.edit().putString("data", "first broken").commit();
        rejected(() -> JsonStoreGuard.read(prefs, "data", schema, "Test store"));
        prefs.edit().putString("data", "second broken").commit();
        rejected(() -> JsonStoreGuard.read(prefs, "data", schema, "Test store"));
        assertEquals("first broken", prefs.getString("data.corrupt_first", ""));
        assertEquals("second broken", prefs.getString("data", ""));
    }

    @Test public void failedCommitRestoresMemoryAndDoesNotAdvanceMigration() throws Exception {
        MemoryPrefs prefs = new MemoryPrefs();
        JSONObject schema = schema();
        String original = valid("old").toString();
        prefs.edit().putString("data", original).commit();
        prefs.failCommits = true;
        rejected(() -> JsonStoreGuard.write(prefs, "data", validUnchecked(), schema, "Test store", "migrated"));
        assertEquals(original, prefs.getString("data", ""));
        assertFalse(prefs.contains("migrated"));
        prefs.failCommits = false;
        rejected(() -> JsonStoreGuard.write(prefs, "data", new JSONArray(), schema, "Test store", null));
        assertEquals(original, prefs.getString("data", ""));
    }
    private JSONArray validUnchecked() {
        try { return valid("new"); } catch (Exception e) { throw new AssertionError(e); }
    }

    @Test public void wrongPreferenceTypeIsPreservedWithoutConversion() throws Exception {
        MemoryPrefs prefs = new MemoryPrefs();
        prefs.edit().putInt("data", 123).commit();
        JSONObject schema = schema();
        rejected(() -> JsonStoreGuard.read(prefs, "data", schema, "Test store"));
        assertEquals(123, prefs.getInt("data", 0));
        assertEquals(123, prefs.getInt("data.corrupt_first", 0));
    }

    @Test public void malformedMigrationFlagCannotBeTreatedAsNotMigrated() {
        MemoryPrefs prefs = new MemoryPrefs();
        prefs.edit().putString("migrated", "bad").commit();
        rejected(() -> JsonStoreGuard.flag(prefs, "migrated", "Test store"));
        assertEquals("bad", prefs.getString("migrated", ""));
    }

    private static final class MemoryPrefs implements SharedPreferences {
        private final Map<String,Object> values = new HashMap<>();
        boolean failCommits;
        public Map<String,?> getAll(){return new HashMap<>(values);}
        public String getString(String k,String d){return values.containsKey(k)?(String)values.get(k):d;}
        @SuppressWarnings("unchecked")
        public Set<String> getStringSet(String k,Set<String>d){return values.containsKey(k)?(Set<String>)values.get(k):d;}
        public int getInt(String k,int d){return values.containsKey(k)?(Integer)values.get(k):d;}
        public long getLong(String k,long d){return values.containsKey(k)?(Long)values.get(k):d;}
        public float getFloat(String k,float d){return values.containsKey(k)?(Float)values.get(k):d;}
        public boolean getBoolean(String k,boolean d){return values.containsKey(k)?(Boolean)values.get(k):d;}
        public boolean contains(String k){return values.containsKey(k);}
        public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l){}
        public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener l){}
        public Editor edit(){return new MemoryEditor();}
        private final class MemoryEditor implements Editor {
            final Map<String,Object> pending=new HashMap<>(); boolean clear;
            public Editor putString(String k,String v){pending.put(k,v);return this;}
            public Editor putStringSet(String k,Set<String>v){pending.put(k,v);return this;}
            public Editor putInt(String k,int v){pending.put(k,v);return this;}
            public Editor putLong(String k,long v){pending.put(k,v);return this;}
            public Editor putFloat(String k,float v){pending.put(k,v);return this;}
            public Editor putBoolean(String k,boolean v){pending.put(k,v);return this;}
            public Editor remove(String k){pending.put(k,null);return this;}
            public Editor clear(){clear=true;return this;}
            public boolean commit(){
                if(clear)values.clear();
                for(Map.Entry<String,Object> e:pending.entrySet())
                    if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());
                return !failCommits;
            }
            public void apply(){commit();}
        }
    }
}
