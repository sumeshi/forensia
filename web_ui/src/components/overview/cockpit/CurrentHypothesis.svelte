<script lang="ts">
  export let title = "アクティブな仮説はありません";
  export let status = "待機";
  export let summary = "";
</script>

<section class="panel p-4">
  <div class="mb-3 flex items-center justify-between gap-2">
    <h3 class="panel-title">Current Hypothesis</h3>
    <span class="chip">{status}</span>
  </div>
  <h4 class="text-sm font-semibold text-mocha-text">{title}</h4>
  <p class="mt-2 text-sm text-mocha-subtext1">{summary}</p>
</section>
