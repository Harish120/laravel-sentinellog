<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('location_verifications', function (Blueprint $table) {
            $table->id();
            $table->string('authenticatable_type');
            $table->unsignedBigInteger('authenticatable_id');
            $table->string('token', 64)->unique();
            $table->string('session_id')->nullable();
            $table->string('ip_address', 45);
            $table->json('location')->nullable();
            $table->text('user_agent')->nullable();
            $table->json('device_info')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('verified_at')->nullable();
            $table->timestamp('denied_at')->nullable();
            $table->timestamps();

            $table->index(['authenticatable_type', 'authenticatable_id'], 'location_verifications_auth_idx');
            $table->index('token');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('location_verifications');
    }
};
